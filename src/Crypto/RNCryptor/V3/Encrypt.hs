{-# LANGUAGE BangPatterns #-}
module Crypto.RNCryptor.V3.Encrypt
  ( pkcs7Padding
  , encrypt
  , encryptBlock
  , encryptStream
  ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Crypto.RNCryptor.Types
import           Crypto.RNCryptor.Padding
import           Crypto.Cipher.AES
import           Data.Monoid
import qualified System.IO.Streams as S


--------------------------------------------------------------------------------
-- | Encrypt a raw Bytestring block. The function returns the encrypt text block
-- plus a new 'RNCryptorContext', which is needed because the IV needs to be
-- set to the last 16 bytes of the previous cipher text. (Thanks to Rob Napier
-- for the insight).
encryptBlock :: RNCryptorContext
             -> ByteString
             -> (RNCryptorContext, ByteString)
encryptBlock ctx clearText = 
  let cipherText  = encryptCBC (ctxCipher ctx) (rncIV . ctxHeader $ ctx) clearText
      !sz        = B.length clearText
      !newHeader = (ctxHeader ctx) { rncIV = (B.drop (sz - 16) clearText) }
      in (ctx { ctxHeader = newHeader }, cipherText)

--------------------------------------------------------------------------------
-- | Encrypt a message. Please be aware that this is a user-friendly
-- but dangerous function, in the sense that it will load the *ENTIRE* input in
-- memory. It's mostly suitable for small inputs like passwords. For large
-- inputs, where size exceeds the available memory, please use 'encryptStream'.
encrypt :: RNCryptorContext -> ByteString -> ByteString
encrypt ctx input =
  let hdr = ctxHeader ctx
      inSz = B.length input
      (_, clearText) = encryptBlock ctx (input <> pkcs7Padding blockSize inSz)
  in renderRNCryptorHeader hdr <> clearText <> (rncHMAC hdr $ mempty)


--------------------------------------------------------------------------------
-- | The 'EncryptionState' the streamer can be at. This is needed to drive the
-- computation as well as reading leftovers unread back in case we need to
-- chop the buffer read, if not multiple of the 'blockSize'.
data EncryptionState =
    Continue
  | FetchLeftOver !Int
  | DrainSource deriving (Show, Eq)

--------------------------------------------------------------------------------
-- | Efficiently encrypt an incoming stream of bytes.
encryptStream :: ByteString
              -- ^ The user key (e.g. password)
              -> S.InputStream ByteString
              -- ^ The input source (mostly likely stdin)
              -> S.OutputStream ByteString
              -- ^ The output source (mostly likely stdout)
              -> IO ()
encryptStream userKey inS outS = do
  hdr <- newRNCryptorHeader userKey
  let ctx = newRNCryptorContext userKey hdr
  S.write (Just $ renderRNCryptorHeader hdr) outS
  go Continue mempty ctx
  where
    slack input = let bsL = B.length input in (bsL, bsL `mod` blockSize)

    go :: EncryptionState -> ByteString -> RNCryptorContext -> IO ()
    go dc !iBuffer ctx = do
      nextChunk <- case dc of
        FetchLeftOver size -> do
          lo <- S.readExactly size inS
          p  <- S.read inS
          return $ fmap (mappend lo) p
        _ -> S.read inS
      case nextChunk of
        Nothing -> finaliseEncryption iBuffer ctx
        (Just v) -> do
          let (sz, sl) = slack v
          case dc of
            DrainSource -> go DrainSource (iBuffer <> v) ctx
            _ -> do
              whatsNext <- S.peek inS
              case whatsNext of
                Nothing -> finaliseEncryption (iBuffer <> v) ctx
                Just nt ->
                  case sz + B.length nt < 4096 of
                    True  -> go DrainSource (iBuffer <> v) ctx
                    False -> do
                      -- If I'm here, it means I can safely decrypt this chunk
                      let (toEncrypt, rest) = B.splitAt (sz - sl) v
                      let (newCtx, cryptoB) = encryptBlock ctx toEncrypt
                      S.write (Just cryptoB) outS
                      case sl == 0 of
                        False -> do
                          S.unRead rest inS
                          go (FetchLeftOver sl) iBuffer newCtx
                        True -> go Continue iBuffer newCtx

    finaliseEncryption lastBlock ctx = do
      let inSz = B.length lastBlock
          padding = pkcs7Padding blockSize inSz
      S.write (Just (snd $ encryptBlock ctx (lastBlock <> padding))) outS
