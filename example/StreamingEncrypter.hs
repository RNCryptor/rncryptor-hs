{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Crypto.RNCryptor.V3.Encrypt
import qualified Data.ByteString.Char8 as B
import           System.Environment
import           System.IO

main :: IO ()
main = do
  args <- getArgs
  case args of
    key:_ -> encryptStream (B.pack key) stdin stdout
    _ -> putStrLn "usage: rncryptor-encrypt <key>"
