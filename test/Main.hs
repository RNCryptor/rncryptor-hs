{-# LANGUAGE OverloadedStrings #-}
module Main where

import qualified PasswordBasedVectors as Pwd
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import           Tests

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
           , testGroup "Password-Based Test Vectors" [
                 testCase "All fields empty or zero" Pwd.allEmptyOrZero
               , testCase "One byte" Pwd.oneByte
               , testCase "Exactly one block" Pwd.exactlyOneBlock
               , testCase "More than one block" Pwd.moreThanOneBlock
               , testCase "Multibyte password" Pwd.multibytePassword
               , testCase "Longer text and password" Pwd.longerTextAndPassword
               ]
         , withQuickCheckDepth "RNCryptor properties" 100 [
             testProperty "encrypt/decrypt roundtrip" testEncryptDecryptRoundtrip
           , testProperty "encrypt/decrypt streaming roundtrip" testStreamingEncryptDecryptRoundtrip
         ]
     ]
