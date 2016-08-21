{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module Tests where

import Test.Tasty.QuickCheck
import Test.Tasty.HUnit
import Crypto.RNCryptor.V3
import Control.Applicative
import qualified Data.ByteString as B


newtype TestVector = TV (UserInput, UserInput, RNCryptorHeader) deriving Show

instance Arbitrary TestVector where
  arbitrary = TV <$> ((,,) <$> arbitrary <*> arbitrary <*> arbitrary)


testEncryptDecryptRoundtrip :: Property
testEncryptDecryptRoundtrip =
  forAll arbitrary $ \(TV (input,pwd,hdr)) ->
    B.length (unInput input) > 0 &&
    B.length (unInput pwd) > 0 ==>
    let ctx = newRNCryptorContext (unInput pwd) hdr
        encrypted = encrypt ctx (unInput input)
    in decrypt encrypted (unInput pwd) == unInput input

--------------------------------------------------------------------------------
-- See: https://github.com/RNCryptor/rncryptor-hs/issues/11
testForeignEncryption :: Assertion
testForeignEncryption = do
  let swiftEncrypted = B.pack [ 3,1,87,71,124,209,185,241,167,159,231,166,42,86
                              , 249,135,241,131,72,179,174,66,55,129,9,123,87
                              , 132,142,56,254,209,105,85,80,12,215,80,221,155
                              , 233,226,46,42,150,167,34,17,77,156,74,75,88,239
                              , 240,196,40,32,213,67,60,223,189,56,94,123,69,93
                              , 247,161,244,207,21,51,231,90,88,198,109,111,174,204
                              ]
  let swiftPassword = B.pack [112,97,115,115,119,111,114,100]
  decrypt swiftEncrypted swiftPassword @=? "01"
