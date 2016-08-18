{-# LANGUAGE BangPatterns #-}
module Crypto.RNCryptor.V3.Stream
  ( processStream
  , StreamingState(..)
  ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Word
import           Control.Monad.State
import           Crypto.RNCryptor.Types
import           Data.Monoid
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
              -> (RNCryptorContext -> ByteString -> (RNCryptorContext, ByteString))
              -- ^ The action to perform over the block
              -> (ByteString -> RNCryptorContext -> IO ())
              -- ^ The finaliser
              -> IO ()
processStream context inS outS blockFn finaliser = go Continue mempty context
  where
    slack input = let bsL = B.length input in (bsL, bsL `mod` blockSize)

    go :: StreamingState -> ByteString -> RNCryptorContext -> IO ()
    go dc !iBuffer ctx = do
      nextChunk <- case dc of
        FetchLeftOver size -> do
          lo <- S.readExactly size inS
          p  <- S.read inS
          return $ fmap (mappend lo) p
        _ -> S.read inS
      case nextChunk of
        Nothing -> finaliser iBuffer ctx
        (Just v) -> do
          let (sz, sl) = slack v
          case dc of
            DrainSource -> go DrainSource (iBuffer <> v) ctx
            _ -> do
              whatsNext <- S.peek inS
              case whatsNext of
                Nothing -> finaliser (iBuffer <> v) ctx
                Just nt ->
                  case sz + B.length nt < 4096 of
                    True  -> go DrainSource (iBuffer <> v) ctx
                    False -> do
                      -- If I'm here, it means I can safely process this chunk
                      let (toProcess, rest) = B.splitAt (sz - sl) v
                      let (newCtx, res) = blockFn ctx toProcess
                      S.write (Just res) outS
                      case sl == 0 of
                        False -> do
                          S.unRead rest inS
                          go (FetchLeftOver sl) iBuffer newCtx
                        True -> go Continue iBuffer newCtx
