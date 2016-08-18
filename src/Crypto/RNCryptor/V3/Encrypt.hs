{-# LANGUAGE BangPatterns #-}
module Crypto.RNCryptor.V3.Encrypt
  ( encrypt
  , encryptBlock
  , encryptStream
  ) where

import           Crypto.Cipher.AES          (AES128)
import           Crypto.Cipher.Types        (makeIV, IV, BlockCipher, cbcEncrypt)
import           Crypto.MAC.HMAC            (update, finalize)
import           Crypto.RNCryptor.Padding
import           Crypto.RNCryptor.Types
import           Crypto.RNCryptor.V3.Stream
import           Data.ByteArray             (convert)
import           Data.ByteString            (ByteString)
import qualified Data.ByteString as B
import           Data.Maybe                 (maybe)
import           Data.Monoid
import qualified System.IO.Streams as S

encrypt_ :: AES128 -> ByteString -> ByteString -> ByteString
encrypt_ a iv clearText =
  cbcEncrypt a iv' clearText
  where
    iv' = maybe (error "encrypt_ failed makeIV") id $ makeIV iv

--------------------------------------------------------------------------------
-- | Encrypt a raw Bytestring block. The function returns the encrypt text block
-- plus a new 'RNCryptorContext', which is needed because the IV needs to be
-- set to the last 16 bytes of the previous cipher text. (Thanks to Rob Napier
-- for the insight).
encryptBlock :: RNCryptorContext
             -> ByteString
             -> (RNCryptorContext, ByteString)
encryptBlock ctx clearText = 
  let cipherText = encrypt_ (ctxCipher ctx) (rncIV . ctxHeader $ ctx) clearText
      !newHmacCtx = update (ctxHMACCtx ctx) cipherText
      !sz         = B.length clearText
      !newHeader  = (ctxHeader ctx) { rncIV = (B.drop (sz - 16) clearText) }
      in (ctx { ctxHeader = newHeader, ctxHMACCtx = newHmacCtx }, cipherText)

--------------------------------------------------------------------------------
-- | Encrypt a message. Please be aware that this is a user-friendly
-- but dangerous function, in the sense that it will load the *ENTIRE* input in
-- memory. It's mostly suitable for small inputs like passwords. For large
-- inputs, where size exceeds the available memory, please use 'encryptStream'.
encrypt :: RNCryptorContext -> ByteString -> ByteString
encrypt ctx input =
  let msgHdr  = renderRNCryptorHeader $ ctxHeader ctx
      ctx'    = ctx { ctxHMACCtx = update (ctxHMACCtx ctx) msgHdr }
      (ctx'', cipherText) = encryptBlock ctx' (input <> pkcs7Padding blockSize (B.length input))
      msgHMAC = convert $ finalize (ctxHMACCtx ctx'')  -- msgHMAC = (rncHMAC hdr) key $ msgHdr <> cipherText
  in msgHdr <> cipherText <> msgHMAC

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
  hdr <- newRNCryptorHeader 
  let ctx     = newRNCryptorContext userKey hdr
      msgHdr  = renderRNCryptorHeader hdr
      ctx'    = ctx { ctxHMACCtx = update (ctxHMACCtx ctx) msgHdr }
  S.write (Just msgHdr) outS
  processStream ctx' inS outS encryptBlock finaliseEncryption
  where
    finaliseEncryption lastBlock ctx = do
      let (ctx', cipherText) = encryptBlock ctx (lastBlock <> pkcs7Padding blockSize (B.length lastBlock))
      S.write (Just cipherText) outS
      S.write (Just (convert $ finalize (ctxHMACCtx ctx'))) outS
