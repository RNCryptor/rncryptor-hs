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
import qualified System.IO.Streams as S


--------------------------------------------------------------------------------
pkcs7Padding :: Int -> Int -> ByteString
pkcs7Padding k l =
  let octetsSize = k - (l `mod` k)
  in  B.pack $ replicate octetsSize (fromInteger . toInteger $ octetsSize)

--------------------------------------------------------------------------------
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
-- | Decrypt a raw Bytestring block
decryptBlock :: RNCryptorContext -> ByteString -> ByteString
decryptBlock ctx = decryptCBC (ctxCipher ctx) (rncIV . ctxHeader $ ctx)

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
decryptStream :: ByteString
              -> S.InputStream ByteString
              -> S.OutputStream ByteString
              -> IO ()
decryptStream userKey inS outS = do
  rawHdr <- S.readExactly 34 inS
  let hdr = parseHeader rawHdr
  let ctx = newRNCryptorContext userKey hdr
  go ctx
  where
    go :: RNCryptorContext -> IO ()
    go ctx= do
      nextChunk <- S.read inS
      case nextChunk of
        Nothing -> return ()
        b@(Just v) -> case B.length v `mod` blockSize of
          0 -> do
            S.write (fmap (decryptBlock ctx) b) outS
            go ctx
          _ -> do
            S.unRead v inS
            finaliseDecryption ctx

    finaliseDecryption ctx = do
      nextChunk <- S.read inS
      case nextChunk of
        Nothing -> return ()
        (Just v) -> do
          let (rest, _) = B.splitAt (B.length v - 32) v --strip the hmac
          let slack = B.length rest `mod` blockSize
          let restToDecrypt = B.take (B.length rest - slack) rest
          S.write (Just $ removePaddingSymbols (decryptBlock ctx restToDecrypt)) outS
