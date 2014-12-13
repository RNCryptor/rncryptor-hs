module Crypto.RNCryptor.Padding
  ( pkcs7Padding ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B


--------------------------------------------------------------------------------
-- | Computes the padding as per PKCS#7. The specification can be found 
-- here: <http://tools.ietf.org/html/rfc5652#section-6.3>
pkcs7Padding :: Int
             -- ^ The block size (e.g. 16 bytes)
             -> Int
             -- ^ The input size
             -> ByteString
             -- ^ The resulting padding
pkcs7Padding k l =
  let octetsSize = k - (l `rem` k)
  in  B.pack $ replicate octetsSize (fromIntegral octetsSize)
