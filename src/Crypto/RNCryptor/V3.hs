{-# LANGUAGE BangPatterns #-}
module Crypto.RNCryptor.V3
  ( pkcs7Padding
  , parseHeader
  , decrypt
  , decryptBlock
  , decryptStream
  ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Word
import           Control.Monad.State
import           Crypto.RNCryptor.Types
import           Crypto.Cipher.AES
import           Data.Monoid
import qualified System.IO.Streams as S


--------------------------------------------------------------------------------
-- | Computes the padding as per PKCS#7. The specification can be found 
-- here: http://tools.ietf.org/html/rfc5652#section-6.3
pkcs7Padding :: Int
             -- ^ The block size (e.g. 16 bytes)
             -> Int
             -- ^ The input size
             -> ByteString
             -- ^ The resulting padding
pkcs7Padding k l =
  let octetsSize = k - (l `mod` k)
  in  B.pack $ replicate octetsSize (fromInteger . toInteger $ octetsSize)

--------------------------------------------------------------------------------
-- | Parse the input 'ByteString' to extract the 'RNCryptorHeader', as 
-- defined in the V3 spec. The incoming 'ByteString' is expected to have
-- at least 34 bytes available. As the HMAC can be found only at the very
-- end of an encrypted file, 'RNCryptorHeader' provides by default a function
-- to parse the HMAC, callable at the right time during streaming/parsing.
parseHeader :: ByteString -> RNCryptorHeader
parseHeader input = flip evalState input $ do
  v <- parseVersion
  o <- parseOptions
  eSalt <- parseEncryptionSalt
  hmacSalt <- parseHMACSalt
  iv <- parseIV
  return RNCryptorHeader {
      rncVersion = v
    , rncOptions = o
    , rncEncryptionSalt = eSalt
    , rncHMACSalt = hmacSalt
    , rncIV = iv
    , rncHMAC = parseHMAC
    }

--------------------------------------------------------------------------------
parseSingleWord8 :: String -> State ByteString Word8
parseSingleWord8 err = do
  bs <- get
  let (v,vs) = B.splitAt 1 bs
  put vs
  case B.unpack v of
    x:[] -> return x
    _ -> fail err

--------------------------------------------------------------------------------
parseBSOfSize :: Int -> String -> State ByteString ByteString
parseBSOfSize sz err = do
  bs <- get
  let (v,vs) = B.splitAt sz bs
  put vs
  case B.unpack v of
    [] -> fail err
    _ -> return v

--------------------------------------------------------------------------------
parseVersion :: State ByteString Word8
parseVersion = parseSingleWord8 "parseVersion: not enough bytes."

--------------------------------------------------------------------------------
parseOptions :: State ByteString Word8
parseOptions = parseSingleWord8 "parseOptions: not enough bytes."

--------------------------------------------------------------------------------
parseEncryptionSalt :: State ByteString ByteString
parseEncryptionSalt = parseBSOfSize 8 "parseEncryptionSalt: not enough bytes."

--------------------------------------------------------------------------------
parseHMACSalt :: State ByteString ByteString
parseHMACSalt = parseBSOfSize 8 "parseHMACSalt: not enough bytes."

--------------------------------------------------------------------------------
parseIV :: State ByteString AESIV
parseIV = fmap aesIV_ (parseBSOfSize 16 "parseIV: not enough bytes.")

--------------------------------------------------------------------------------
parseHMAC :: ByteString -> ByteString
parseHMAC leftover = flip evalState leftover $ parseBSOfSize 32 "parseHMAC: not enough bytes."

--------------------------------------------------------------------------------
blockSize :: Int
blockSize = 16

--------------------------------------------------------------------------------
-- | This was taken directly from the Python implementation, see "post_decrypt_data",
-- even though it doesn't seem to be a usual PKCS#7 removal:
-- data = data[:-bord(data[-1])]
-- https://github.com/RNCryptor/RNCryptor-python/blob/master/RNCryptor.py#L69
removePaddingSymbols :: ByteString -> ByteString
removePaddingSymbols input = 
  let lastWord = B.last input
  in B.take (B.length input - fromEnum lastWord) input

--------------------------------------------------------------------------------
-- | Decrypt a raw Bytestring block. The function returns the clear text block
-- plus a new 'RNCryptorContext', which is needed because the IV needs to be
-- set to the last 16 bytes of the previous cipher text. (Thanks to Rob Napier
-- for the insight).
decryptBlock :: RNCryptorContext
             -> ByteString
             -> (RNCryptorContext, ByteString)
decryptBlock ctx cipherText = 
  let clearText  = decryptCBC (ctxCipher ctx) (rncIV . ctxHeader $ ctx) cipherText
      !sz        = B.length cipherText
      !newHeader = (ctxHeader ctx) { rncIV = aesIV_ (B.drop (sz - 16) cipherText) }
      in (ctx { ctxHeader = newHeader }, clearText)

--------------------------------------------------------------------------------
-- | Decrypt an encrypted message. Please be aware that this is a user-friendly
-- but dangerous function, in the sense that it will load the *ENTIRE* input in
-- memory. It's mostly suitable for small inputs like passwords. For large
-- inputs, where size exceeds the available memory, please use 'decryptStream'.
decrypt :: ByteString -> ByteString -> ByteString
decrypt input pwd =
  let (rawHdr, rest) = B.splitAt 34 input
      -- remove the hmac at the end of the file
      (toDecrypt, _) = B.splitAt (B.length rest - 32) rest
      hdr = parseHeader rawHdr
      ctx = newRNCryptorContext pwd hdr
      clearText = decryptCBC (ctxCipher ctx) (rncIV . ctxHeader $ ctx) toDecrypt
  in  removePaddingSymbols clearText


--------------------------------------------------------------------------------
-- | The 'DecryptionState' the streamer can be at. This is needed to drive the
-- computation as well as reading leftovers unread back in case we need to
-- chop the buffer read, if not multiple of the 'blockSize'.
data DecryptionState =
    Continue
  | FetchLeftOver !Int
  | DrainSource deriving (Show, Eq)

--------------------------------------------------------------------------------
decryptStream :: ByteString
              -> S.InputStream ByteString
              -> S.OutputStream ByteString
              -> IO ()
decryptStream userKey inS outS = do
  rawHdr <- S.readExactly 34 inS
  let hdr = parseHeader rawHdr
  let ctx = newRNCryptorContext userKey hdr
  go Continue mempty ctx
  where
    slack input = let bsL = B.length input in (bsL, bsL `mod` blockSize)

    go :: DecryptionState -> ByteString -> RNCryptorContext -> IO ()
    go dc !iBuffer ctx = do
      nextChunk <- case dc of
        FetchLeftOver size -> do
          lo <- S.readExactly size inS
          p  <- S.read inS
          return $ fmap (mappend lo) p
        _ -> S.read inS
      case nextChunk of
        Nothing -> finaliseDecryption iBuffer ctx
        (Just v) -> do
          let (sz, sl) = slack v
          case dc of
            DrainSource -> go DrainSource (iBuffer <> v) ctx
            _ -> do
              whatsNext <- S.peek inS
              case whatsNext of
                Nothing -> finaliseDecryption (iBuffer <> v) ctx
                Just nt ->
                  case sz + B.length nt < 4096 of
                    True  -> go DrainSource (iBuffer <> v) ctx
                    False -> do
                      -- If I'm here, it means I can safely decrypt this chunk
                      let (toDecrypt, rest) = B.splitAt (sz - sl) v
                      let (newCtx, clearT) = decryptBlock ctx toDecrypt
                      S.write (Just $ clearT) outS
                      S.unRead rest inS
                      go (FetchLeftOver sl) iBuffer newCtx

    finaliseDecryption lastBlock ctx = do
      let (rest, _) = B.splitAt (B.length lastBlock - 32) lastBlock --strip the hmac
      S.write (Just $ removePaddingSymbols (snd $ decryptBlock ctx rest)) outS
