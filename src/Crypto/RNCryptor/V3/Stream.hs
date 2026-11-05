{-# LANGUAGE BangPatterns #-}
module Crypto.RNCryptor.V3.Stream
  ( processStream
  ) where

import           Crypto.RNCryptor.Types
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified System.IO.Streams as S

-- | Drive a block transform over an input stream in constant memory. Whole
-- blocks are transformed and written as soon as they are available; the last
-- 'holdBack' bytes are never transformed here and are handed to the finaliser
-- at end of input.
processStream :: Int
              -- ^ How many trailing bytes the finaliser needs to see
              -- untouched (decrypt: last block + HMAC, encrypt: 0).
              -> RNCryptorContext
              -- ^ The RNCryptor context for this operation
              -> S.InputStream ByteString
              -- ^ The input source (mostly likely stdin)
              -> S.OutputStream ByteString
              -- ^ The output source (mostly likely stdout)
              -> (RNCryptorContext -> ByteString -> (RNCryptorContext, ByteString))
              -- ^ The action to perform over the block
              -> (ByteString -> RNCryptorContext -> IO ())
              -- ^ The finaliser
              -> IO ()
processStream holdBack context inS outS applyToBlock finaliser = go B.empty context
  where
    -- 'carry' stays below holdBack + blockSize bytes: anything beyond that is
    -- a whole block and gets transformed on the read that completes it. That
    -- bound is what keeps memory independent of input size and of how the
    -- input is chunked. The only end-of-input signal is 'S.read' returning
    -- 'Nothing'; no peeking, no guessing from chunk sizes.
    go !carry !ctx = do
      mchunk <- S.read inS
      case mchunk of
        Nothing    -> finaliser carry ctx
        Just chunk -> do
          let buf         = carry <> chunk
              processable = ((B.length buf - holdBack) `div` blockSize) * blockSize
          if processable <= 0
            then go buf ctx
            else do
              let (blocks, rest) = B.splitAt processable buf
                  (ctx', out)    = applyToBlock ctx blocks
              S.write (Just out) outS
              go rest ctx'
