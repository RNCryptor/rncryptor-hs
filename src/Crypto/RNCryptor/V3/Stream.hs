{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE UnboxedTuples #-}
module Crypto.RNCryptor.V3.Stream
  ( processStream
  , StreamingState(..)
  ) where

import           ByteString.TreeBuilder as TB
import           Control.Monad.State
import           Crypto.RNCryptor.Types
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Monoid
import           Data.Word
import qualified System.IO.Streams as S

--------------------------------------------------------------------------------
-- | The 'StreamingState' the streamer can be at. This is needed to drive the
-- computation as well as reading leftovers unread back in case we need to
-- chop the buffer read, if not multiple of the 'blockSize'.
data StreamingState =
    Continue
  | FetchLeftOver !Int
  | DrainSource deriving (Show, Eq)

--------------------------------------------------------------------------------
-- | Efficiently transform an incoming stream of bytes.
processStream :: RNCryptorContext
              -- ^ The RNCryptor context for this operation
              -> S.InputStream ByteString
              -- ^ The input source (mostly likely stdin)
              -> S.OutputStream ByteString
              -- ^ The output source (mostly likely stdout)
              -> (RNCryptorContext -> ByteString -> (# RNCryptorContext, ByteString #))
              -- ^ The action to perform over the block
              -> (ByteString -> RNCryptorContext -> IO ())
              -- ^ The finaliser
              -> IO ()
processStream context inS outS blockFn finaliser = do
  processBlock Continue mempty context
  where
    slack input = let bsL = B.length input in (# bsL, bsL `mod` blockSize #)

    processBlock :: StreamingState -> TB.Builder -> RNCryptorContext -> IO ()
    processBlock dc iBuffer ctx = do
      nextChunk <- readNextChunk inS dc
      case nextChunk of
        Nothing -> finaliser (TB.toByteString iBuffer) ctx
        Just v -> do
          let (# sz, sl #) = slack v
          case dc of
            DrainSource -> processBlock DrainSource (iBuffer <> TB.byteString v) ctx
            _ -> do
              whatsNext <- S.peek inS
              case whatsNext of
                Nothing -> finaliser (TB.toByteString (iBuffer <> TB.byteString v)) ctx
                Just nt ->
                  case sz + B.length nt < 4096 of
                    True  -> processBlock DrainSource (iBuffer <> TB.byteString v) ctx
                    False -> do
                      -- If I'm here, it means I can safely process this chunk
                      let (toProcess, rest) = B.splitAt (sz - sl) v
                      let (# newCtx, res #) = blockFn ctx toProcess
                      S.write (Just res) outS
                      S.write (Just mempty) outS -- explicit flush.
                      case sl == 0 of
                        False -> do
                          S.unRead rest inS
                          processBlock (FetchLeftOver sl) iBuffer newCtx
                        True -> processBlock Continue iBuffer newCtx

--------------------------------------------------------------------------------
readNextChunk :: S.InputStream ByteString -> StreamingState -> IO (Maybe ByteString)
readNextChunk inS streamingState = case streamingState of
    FetchLeftOver size -> do
      lo <- S.readExactly size inS
      p  <- S.read inS
      return $! fmap (mappend lo) p
    _ -> S.read inS
