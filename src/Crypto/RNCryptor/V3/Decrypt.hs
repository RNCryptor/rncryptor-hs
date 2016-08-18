{-# LANGUAGE BangPatterns #-}
module Crypto.RNCryptor.V3.Decrypt
  ( parseHeader
  , decrypt
  , decryptBlock
  , decryptStream
  ) where

import           Control.Monad.State
import           Crypto.Cipher.AES           (AES128)
import           Crypto.Cipher.Types         (IV, makeIV, BlockCipher, cbcDecrypt)
import           Crypto.RNCryptor.Types
import           Crypto.RNCryptor.V3.Stream
import           Data.ByteString             (ByteString)
import qualified Data.ByteString as B
import           Data.Maybe                  (maybe)
import           Data.Monoid
import           Data.Word
import qualified System.IO.Streams as S

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
    , rncHMAC = \bs pwd -> error "internal error, uninitialized HMAC alg"
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
parseIV :: State ByteString ByteString
parseIV = parseBSOfSize 16 "parseIV: not enough bytes."

--------------------------------------------------------------------------------
parseHMAC :: ByteString -> ByteString
parseHMAC leftover = flip evalState leftover $ parseBSOfSize 32 "parseHMAC: not enough bytes."

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
decrypt_ :: AES128 -> ByteString -> ByteString -> ByteString
decrypt_ a iv cipherText =
  cbcDecrypt a iv' cipherText
  where
    iv' = maybe (error "decrypt_ failed makeIV") id $ makeIV iv

--------------------------------------------------------------------------------
-- | Decrypt a raw Bytestring block. The function returns the clear text block
-- plus a new 'RNCryptorContext', which is needed because the IV needs to be
-- set to the last 16 bytes of the previous cipher text. (Thanks to Rob Napier
-- for the insight).
decryptBlock :: RNCryptorContext
             -> ByteString
             -> (RNCryptorContext, ByteString)
decryptBlock ctx cipherText = 
  let clearText  = decrypt_ (ctxCipher ctx) (rncIV . ctxHeader $ ctx) cipherText
      !sz        = B.length cipherText
      !newHeader = (ctxHeader ctx) { rncIV = (B.drop (sz - 16) cipherText) }
      in (ctx { ctxHeader = newHeader }, clearText)

--------------------------------------------------------------------------------
consistentTimeEqual :: ByteString -> ByteString -> Bool
consistentTimeEqual a b = and $ B.zipWith (==) a b

--------------------------------------------------------------------------------
-- | Decrypt an encrypted message. Please be aware that this is a user-friendly
-- but dangerous function, in the sense that it will load the *ENTIRE* input in
-- memory. It's mostly suitable for small inputs like passwords. For large
-- inputs, where size exceeds the available memory, please use 'decryptStream'.
decrypt :: ByteString -> ByteString -> ByteString
decrypt input pwd =
  let (rawHdr, rest) = B.splitAt 34 input
      -- remove the hmac at the end of the file
      (cipherText, msgHMAC) = B.splitAt (B.length rest - 32) rest
      hdr = parseHeader $ rawHdr
      ctx = newRNCryptorContext pwd hdr
      clearText = decrypt_ (ctxCipher ctx) (rncIV . ctxHeader $ ctx) cipherText
      hmac = makeHMAC (rncHMACSalt . ctxHeader $ ctx)  pwd $ rawHdr <> cipherText
  in
    if consistentTimeEqual msgHMAC hmac then removePaddingSymbols clearText else error "failed decrypt, invalid HMAC"

--------------------------------------------------------------------------------
-- | Efficiently decrypts an incoming stream of bytes.
decryptStream :: ByteString
              -- ^ The user key (e.g. password)
              -> S.InputStream ByteString
              -- ^ The input source (mostly likely stdin)
              -> S.OutputStream ByteString
              -- ^ The output source (mostly likely stdout)
              -> IO ()
decryptStream userKey inS outS = do
  rawHdr <- S.readExactly 34 inS
  let hdr = parseHeader rawHdr
  let ctx = newRNCryptorContext userKey hdr
  processStream ctx inS outS decryptBlock finaliseDecryption
  where
    finaliseDecryption lastBlock ctx = do
      let (rest, _) = B.splitAt (B.length lastBlock - 32) lastBlock --strip the hmac
      S.write (Just $ removePaddingSymbols (snd $ decryptBlock ctx rest)) outS
