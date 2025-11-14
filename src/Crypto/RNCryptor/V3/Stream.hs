{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use if" #-}
module Crypto.RNCryptor.V3.Stream
  ( processStream
  ) where

import           Control.Monad.State
import           Crypto.RNCryptor.Types
import           Data.Bifunctor
import           Data.ByteString (ByteString)
import           Data.Foldable (foldlM)
import           Data.Monoid
import           Data.Word
import qualified Data.ByteString as B
import qualified System.IO.Streams as S
import Data.Maybe (isNothing)
import Control.Exception

newtype Block
  = Block { _Block :: ByteString }
  deriving (Show, Eq)

-- | Splits the input string into blocks of size 'blockSize' and returns them
-- alongside the leftover.
--getBlocks :: ByteString -> ([Block], B.ByteString)
--getBlocks bs = go (B.splitAt blockSize bs)
--  where
--    go :: (ByteString, ByteString) -> ([Block], ByteString)
--    go (candidateBlock, leftover)
--      | B.length candidateBlock < blockSize
--      = ([], candidateBlock <> leftover)
--      | otherwise
--      = first (\x -> Block candidateBlock : x) $ go (B.splitAt blockSize leftover)

getBlocks :: ByteString -> (ByteString, ByteString)
getBlocks input =
  let bsL = B.length input
      num = bsL `div` blockSize
  in B.splitAt (num * blockSize) input

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
processStream context inS outS applyToBlock finaliser = do
  rawBytes <- S.read inS
  uncurry finaliser =<< go rawBytes context
  where

    go :: Maybe ByteString -> RNCryptorContext -> IO (ByteString, RNCryptorContext)
    go readBytes currentContext = case readBytes of
      Nothing    -> pure (mempty, currentContext)
      Just bytes -> do
        -- check if there is more.
        next <- S.peek inS
        case next of
          Nothing  -> pure (bytes, currentContext)
          Just nxt
            -- If the length of what we still have to read is less than 32 bytes
            -- it means we have read in the middle of the HMAC, which means we
            -- need to stop as this would be our last block.
            | B.length nxt < 32
            -> do
              drained <- S.toList inS
              pure (bytes <> mconcat drained, currentContext)
            | otherwise
            -> do
              let (blocks, leftover) = getBlocks bytes
              case B.null blocks of
                True -> throwIO $ ImpossibleNoMoreBlocks leftover
                _    -> do
                  ctx' <- processBlocks currentContext blocks
                  rawBytes <- S.read inS
                  go (maybe (Just leftover) (\x -> Just $ leftover <> x) rawBytes) ctx'

    processBlocks :: RNCryptorContext -> ByteString -> IO RNCryptorContext
    processBlocks currentContext blocks = do
      let (ctx', text) = applyToBlock currentContext blocks
      S.write (Just text) outS
      pure ctx'
