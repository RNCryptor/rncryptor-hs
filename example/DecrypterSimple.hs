module Main where

import Crypto.RNCryptor.V3.Decrypt
import System.Environment
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString as BIO
import Control.Exception (throwIO)

main :: IO ()
main = do
  args <- getArgs
  case args of
    file:key:_ -> do
      input <- BIO.readFile file
      case decrypt input (B.pack key) of
        Left err  -> throwIO $ userError (show err)
        Right txt -> BIO.writeFile "/dev/stdout" txt
