{-# LANGUAGE OverloadedStrings #-}
module Main where

import Crypto.RNCryptor.V3.Encrypt
import qualified System.IO.Streams as S
import System.Environment
import qualified Data.ByteString.Char8 as B

main :: IO ()
main = do
  args <- getArgs
  case args of
    key:_ -> encryptStream (B.pack key) S.stdin S.stdout
    _ -> putStrLn "usage: rncryptor-encrypt <key>"
