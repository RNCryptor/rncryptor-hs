{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Crypto.RNCryptor.V3.Decrypt
import qualified Data.ByteString.Char8 as B
import           System.Environment
import           System.IO
import qualified System.IO.Streams as S

main :: IO ()
main = do
  args <- getArgs
  case args of
    key:_ -> do
      hSetBuffering stdin  NoBuffering
      hSetBuffering stdout NoBuffering
      decryptStream (B.pack key) S.stdin S.stdout
    _ -> putStrLn "usage: rncryptor-decrypt <key>"
