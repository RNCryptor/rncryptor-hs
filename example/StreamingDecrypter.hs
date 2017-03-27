{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Crypto.RNCryptor.V3.Decrypt
import qualified Data.ByteString.Char8 as B
import           System.Environment
import           System.IO

main :: IO ()
main = do
  args <- getArgs
  case args of
    key:_ -> do
      hSetBuffering stdin  NoBuffering
      hSetBuffering stdout NoBuffering
      decryptStream (B.pack key) stdin stdout
    _ -> putStrLn "usage: rncryptor-decrypt <key>"
