{-# LANGUAGE BangPatterns #-}
module Crypto.RNCryptor.V3.Encrypt
  ( pkcs7Padding
  , encrypt
  , encryptBlock
  -- , encryptStream
  ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Word
import           Control.Monad.State
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

-- --------------------------------------------------------------------------------
-- -- | Efficiently decrypts an incoming stream of bytes.
-- decryptStream :: ByteString
--               -- ^ The user key (e.g. password)
--               -> S.InputStream ByteString
--               -- ^ The input source (mostly likely stdin)
--               -> S.OutputStream ByteString
--               -- ^ The output source (mostly likely stdout)
--               -> IO ()
-- decryptStream userKey inS outS = do
--   rawHdr <- S.readExactly 34 inS
--   let hdr = parseHeader rawHdr
--   let ctx = newRNCryptorContext userKey hdr
--   go Continue mempty ctx
--   where
--     slack input = let bsL = B.length input in (bsL, bsL `mod` blockSize)
-- 
--     go :: DecryptionState -> ByteString -> RNCryptorContext -> IO ()
--     go dc !iBuffer ctx = do
--       nextChunk <- case dc of
--         FetchLeftOver size -> do
--           lo <- S.readExactly size inS
--           p  <- S.read inS
--           return $ fmap (mappend lo) p
--         _ -> S.read inS
--       case nextChunk of
--         Nothing -> finaliseDecryption iBuffer ctx
--         (Just v) -> do
--           let (sz, sl) = slack v
--           case dc of
--             DrainSource -> go DrainSource (iBuffer <> v) ctx
--             _ -> do
--               whatsNext <- S.peek inS
--               case whatsNext of
--                 Nothing -> finaliseDecryption (iBuffer <> v) ctx
--                 Just nt ->
--                   case sz + B.length nt < 4096 of
--                     True  -> go DrainSource (iBuffer <> v) ctx
--                     False -> do
--                       -- If I'm here, it means I can safely decrypt this chunk
--                       let (toDecrypt, rest) = B.splitAt (sz - sl) v
--                       let (newCtx, clearT) = decryptBlock ctx toDecrypt
--                       S.write (Just $ clearT) outS
--                       S.unRead rest inS
--                       go (FetchLeftOver sl) iBuffer newCtx
-- 
--     finaliseDecryption lastBlock ctx = do
--       let (rest, _) = B.splitAt (B.length lastBlock - 32) lastBlock --strip the hmac
--       S.write (Just $ removePaddingSymbols (snd $ decryptBlock ctx rest)) outS
