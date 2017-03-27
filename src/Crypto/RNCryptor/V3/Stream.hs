{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UnboxedTuples #-}
module Crypto.RNCryptor.V3.Stream
  ( processStream
  ) where

import           Control.Monad.State
import           Crypto.RNCryptor.Types
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Monoid
import           Data.Word
import qualified Streaming.Prelude as S
import           System.IO as IO

--------------------------------------------------------------------------------
-- | Efficiently transform an incoming stream of bytes.
processStream :: RNCryptorContext
              -- ^ The RNCryptor context for this operation
              -> Handle
              -- ^ The input Handle (mostly likely stdin)
              -> Handle
              -- ^ The output Handle (mostly likely stdout)
              -> (RNCryptorContext -> ByteString -> (# RNCryptorContext, ByteString #))
              -- ^ The action to perform over the block
              -> (ByteString -> RNCryptorContext -> IO ())
              -- ^ The finaliser
              -> IO ()
processStream context inHandle outHandle blockFn finaliser = do
  let inS = fromHandle inHandle 64000
  processBlock inS mempty context
  where
    slack input = let bsL = B.length input in (# bsL, bsL `mod` blockSize #)

    processBlock :: EncryptedStream -> B.ByteString -> RNCryptorContext -> IO ()
    processBlock inS !leftover ctx = do
      nextChunk <- S.uncons inS
      case nextChunk of
        Nothing      -> finaliser leftover ctx
        Just ("", _) -> finaliser leftover ctx
        Just (currentBlock, nextStream) -> do
          whatsNext <- S.uncons nextStream
          case whatsNext of
            Nothing      -> finaliser (leftover <> currentBlock) ctx
            Just ("", _) -> finaliser (leftover <> currentBlock) ctx
            Just (lookAheadChunk, lookAheadStream)  -> do
              let toDecrypt = leftover <> currentBlock <> lookAheadChunk
              let (# sz, sl #) = slack toDecrypt
              let (toProcess, rest) = B.splitAt (sz - sl) toDecrypt
              let (# newCtx, res #) = blockFn ctx toProcess
              B.hPut outHandle res
              hFlush outHandle
              case sl == 0 of
                True  -> processBlock nextStream mempty newCtx
                False -> processBlock nextStream rest newCtx


type EncryptedStream = S.Stream (S.Of B.ByteString) IO ()

--------------------------------------------------------------------------------
fromHandle :: IO.Handle -> Int -> EncryptedStream
fromHandle h bufSize = go
  where
    go = do
        eof <- liftIO $ IO.hIsEOF h
        unless eof $ do
            str <- liftIO $ B.hGet h bufSize
            S.yield str
            go
{-# INLINABLE fromHandle #-}
