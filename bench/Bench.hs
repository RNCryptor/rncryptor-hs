{-# LANGUAGE OverloadedStrings #-}
module Main where

import Criterion.Main
import Crypto.RNCryptor.Types
import Crypto.RNCryptor.V3.Encrypt
import Data.ByteString as B

encryptBench :: ByteString -> ByteString
encryptBench input =
  let eSalt  = B.pack [0,1,2,3,4,5,6,7]
      hSalt  = B.pack [1,2,3,4,5,6,7,8]
      iv     = B.pack [2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,1]
      header = newRNCryptorHeaderFrom eSalt hSalt iv
      ctx    = newRNCryptorContext "password" header
  in encrypt ctx input

main :: IO ()
main = defaultMain [
  bgroup "encryption" [ bench "simple encryption" $ nf encryptBench "bench"
                      , bench "long encryption"   $ nf encryptBench (B.pack $ Prelude.replicate 1000000 0x0)
                      ]
  ]
