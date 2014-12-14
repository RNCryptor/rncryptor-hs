{-# LANGUAGE ScopedTypeVariables #-}
module Tests where

import Test.Tasty.QuickCheck
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
