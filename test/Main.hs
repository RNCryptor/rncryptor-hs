{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Tests
import           Test.Tasty
import           Test.Tasty.QuickCheck

----------------------------------------------------------------------
withQuickCheckDepth :: TestName -> Int -> [TestTree] -> TestTree
withQuickCheckDepth tn depth tests =
  localOption (QuickCheckTests depth) (testGroup tn tests)

----------------------------------------------------------------------
main :: IO ()
main = do
  defaultMainWithIngredients defaultIngredients $
    testGroup "RNCryptor tests" $ [
         withQuickCheckDepth "RNCryptor properties" 100 [
           testProperty "encrypt/decrypt roundtrip" testEncryptDecryptRoundtrip
         ]
     ]
