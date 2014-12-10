{-# LANGUAGE OverloadedStrings #-}
module Main where

import           System.Environment
import           Data.Monoid
import           Tests
import           Test.Tasty
import           Test.Tasty.HUnit
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
         testGroup "RNCryptor properties" []
     ]
