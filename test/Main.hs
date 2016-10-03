{-# LANGUAGE OverloadedStrings #-}
module Main where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Tests

----------------------------------------------------------------------
withQuickCheckDepth :: TestName -> Int -> [TestTree] -> TestTree
withQuickCheckDepth tn depth tests =
  localOption (QuickCheckTests depth) (testGroup tn tests)

----------------------------------------------------------------------
main :: IO ()
main = do
  defaultMainWithIngredients defaultIngredients $
    testGroup "RNCryptor tests" $ [
           testCase "Swift-encrypted input can be decrypted" testForeignEncryption
         , withQuickCheckDepth "RNCryptor properties" 100 [
             testProperty "encrypt/decrypt roundtrip" testEncryptDecryptRoundtrip
           , testProperty "encrypt/decrypt streaming roundtrip" testStreamingEncryptDecryptRoundtrip
         ]
     ]
