{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use if" #-}
module Crypto.RNCryptor.V3.Decrypt
  ( parseHeader
  , decrypt
  , decryptBlock
  , decryptStream
  , decryptStreamLenient
  ) where

import           Control.Exception           (throwIO, Exception (..))
import           Control.Monad               (unless)
import           Control.Monad.State
import           Crypto.Cipher.AES           (AES256)
import           Crypto.Cipher.Types         (IV, makeIV, BlockCipher, cbcDecrypt)
import           Crypto.MAC.HMAC             (update, finalize)
import           Crypto.RNCryptor.Types
import           Crypto.RNCryptor.V3.Stream
import           Data.Bits                   (xor, (.|.))
import           Data.ByteArray              (convert)
import           Data.ByteString             (ByteString)
import           Data.Foldable
import           Data.Maybe                  (fromMaybe)
import           Data.Monoid
import           Data.Word
import           System.Exit (exitFailure)
import           System.IO (hPutStrLn, stderr)
import qualified Data.ByteString as B
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
    }

--------------------------------------------------------------------------------
parseSingleWord8 :: String -> State ByteString Word8
parseSingleWord8 err = do
  bs <- get
  let (v,vs) = B.splitAt 1 bs
  put vs
  case B.unpack v of
    [x] -> return x
    _   -> error err

--------------------------------------------------------------------------------
parseBSOfSize :: Int -> String -> State ByteString ByteString
parseBSOfSize sz err = do
  bs <- get
  let (v,vs) = B.splitAt sz bs
  put vs
  case B.unpack v of
    [] -> error err
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
-- | This was taken directly from the Python implementation, see "post_decrypt_data",
-- even though it doesn't seem to be a usual PKCS#7 removal:
-- data = data[:-bord(data[-1])]
-- https://github.com/RNCryptor/RNCryptor-python/blob/master/RNCryptor.py#L69
removePaddingSymbols :: ByteString -> ByteString
removePaddingSymbols input
  | B.null input = input
  | otherwise =
      let lastByte = B.last input
          padLength = fromEnum lastByte
      in if padLength <= 16 && padLength <= B.length input
           then B.take (B.length input - padLength) input
           else input -- Invalid padding byte, return original input

--------------------------------------------------------------------------------
decryptBytes :: AES256 -> ByteString -> ByteString -> ByteString
decryptBytes a iv = cbcDecrypt a iv'
  where
    iv' = fromMaybe (error "decryptBytes: makeIV failed.") $ makeIV iv

--------------------------------------------------------------------------------
-- | Decrypt a raw Bytestring block. The function returns the clear text block
-- plus a new 'RNCryptorContext', which is needed because the IV needs to be
-- set to the last 16 bytes of the previous cipher text. (Thanks to Rob Napier
-- for the insight).
decryptBlock :: RNCryptorContext
             -> ByteString
             -> (RNCryptorContext, ByteString)
decryptBlock ctx cipherText =
  let clearText   = decryptBytes (ctxCipher ctx) (rncIV . ctxHeader $ ctx) cipherText
      !newHMACCtx = update (ctxHMACCtx ctx) cipherText
      !sz         = B.length cipherText
      !newHeader  = (ctxHeader ctx) { rncIV = B.drop (sz - 16) cipherText }
      in (ctx { ctxHeader = newHeader, ctxHMACCtx = newHMACCtx }, clearText)

--------------------------------------------------------------------------------
-- "A consistent time function needs to be clear on which parameter is secret and
-- which one is untrusted. Your complexity must always be proportional to the length
-- of the untrusted data, not the secret."
--
-- Below, untrusted == arrived in the message, secret == computed
--
consistentTimeEqual :: ByteString -> ByteString -> Bool
consistentTimeEqual untrusted secret =
  let (initialResult :: Word8) = if B.length secret == B.length untrusted then 0 else 1
      secretCycle = cycle (B.unpack secret)
      xorResults = zipWith xor (B.unpack untrusted) secretCycle
  in 0 == foldl' (.|.) initialResult xorResults

--------------------------------------------------------------------------------
-- | Decrypt an encrypted message. Please be aware that this is a user-friendly
-- but dangerous function, in the sense that it will load the *ENTIRE* input in
-- memory. It's mostly suitable for small inputs like passwords. For large
-- inputs, where size exceeds the available memory, please use 'decryptStream'.
--
-- Returns either the reason for failure, or the successfully decrypted message.
decrypt :: ByteString -> ByteString -> Either RNCryptorException ByteString
decrypt input pwd =
  let (rawHdr, rest) = B.splitAt 34 input
      -- remove the hmac at the end of the file
      (cipherText, msgHMAC) = B.splitAt (B.length rest - 32) rest
      hdr = parseHeader rawHdr
      ctx = newRNCryptorContext pwd hdr
      clearText = decryptBytes (ctxCipher ctx) (rncIV . ctxHeader $ ctx) cipherText
      hmac = makeHMAC (rncHMACSalt . ctxHeader $ ctx) pwd $ rawHdr <> cipherText
  in case consistentTimeEqual msgHMAC hmac of
       True  -> Right (removePaddingSymbols clearText)
       False -> Left (InvalidHMACException msgHMAC hmac)


data OnHMACFailure
  = OHF_abort
  -- | Not recommended for production systems, but useful for debugging.
  | OHF_emit_warning

--------------------------------------------------------------------------------
-- | Efficiently decrypts an incoming stream of bytes.
decryptStreamWith :: OnHMACFailure
                  -> ByteString
                  -- ^ The user key (e.g. password)
                  -> S.InputStream ByteString
                  -- ^ The input source (mostly likely stdin)
                  -> S.OutputStream ByteString
                  -- ^ The output source (mostly likely stdout)
                  -> IO ()
decryptStreamWith onInvalidHMAC userKey inS outS = do
  rawHdr <- S.readExactly 34 inS
  let hdr = parseHeader rawHdr
      ctx = newRNCryptorContext userKey hdr
      ctx' = ctx { ctxHMACCtx = update (ctxHMACCtx ctx) rawHdr }
  processStream ctx' inS outS decryptBlock finaliseDecryption
  where
    finaliseDecryption lastBlock ctx = do
      let (cipherText, msgHMAC) = B.splitAt (B.length lastBlock - 32) lastBlock
          (ctx', clearText)     = decryptBlock ctx cipherText
          hmac = convert $ finalize (ctxHMACCtx ctx')
      S.write (Just $ removePaddingSymbols clearText) outS
      let invalidHMacEx = InvalidHMACException msgHMAC hmac
      case consistentTimeEqual msgHMAC hmac of
        True  -> pure ()
        False -> case onInvalidHMAC of
          OHF_abort        -> throwIO invalidHMacEx
          OHF_emit_warning -> do
            hPutStrLn stderr (displayException invalidHMacEx)
            exitFailure

--------------------------------------------------------------------------------
-- | Efficiently decrypts an incoming stream of bytes.
decryptStream :: ByteString
              -- ^ The user key (e.g. password)
              -> S.InputStream ByteString
              -- ^ The input source (mostly likely stdin)
              -> S.OutputStream ByteString
              -- ^ The output source (mostly likely stdout)
              -> IO ()
decryptStream = decryptStreamWith OHF_abort

--------------------------------------------------------------------------------
-- | Efficiently decrypts an incoming stream of bytes, not failing if the
-- stream fails HMAC validation.
decryptStreamLenient :: ByteString
                     -- ^ The user key (e.g. password)
                     -> S.InputStream ByteString
                     -- ^ The input source (mostly likely stdin)
                     -> S.OutputStream ByteString
                     -- ^ The output source (mostly likely stdout)
                     -> IO ()
decryptStreamLenient = decryptStreamWith OHF_emit_warning
