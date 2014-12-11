{-# LANGUAGE OverloadedStrings #-}
module Main where

import Crypto.RNCryptor.V3
import qualified System.IO.Streams as S
import System.Environment
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8 as B

testVector = Base64.decodeLenient "AwHadtV3t/3C1Fy//3KXgoxfLTVB9utAU0TOQHCbPnB2kd1TEzeos+KROD5zS/DbVUD/S1vFebqk/Mhdo8JhmEgpZr62T2mK3fh542TPxF2d/wW7h1gbOtybt+rV0xCkGx0Qs6MNW5U0yDmrSP9Q5Ko8MjMx/nKtyA7PfCYOmiDFJdZUXaH5qdpavRpkF6y0/8g="

main :: IO ()
main = do
  args <- getArgs
  case args of
    "test":_ -> print $ Base64.encode $ decrypt testVector (B.pack "stupid")
    key:_ -> decryptStream (B.pack key) S.stdin S.stdout
    _ -> putStrLn "usage: rncryptor-stream <key>"
