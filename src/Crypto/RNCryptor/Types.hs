{-# LANGUAGE RecordWildCards #-}
module Crypto.RNCryptor.Types 
     ( RNCryptorHeader(..)
     , RNCryptorContext(ctxHeader, ctxCipher)
     , UserInput(..)
     , newRNCryptorContext
     , newRNCryptorHeader
     , renderRNCryptorHeader
     , blockSize
     ) where

import Data.ByteString (cons, ByteString)
import qualified Data.ByteString.Char8 as C8
import Data.Word
import Data.Monoid
import System.Random
import Control.Applicative
import Control.Monad
import Crypto.Cipher.AES
import Crypto.PBKDF.ByteString
import Test.QuickCheck


data RNCryptorHeader = RNCryptorHeader {
        rncVersion :: !Word8
      -- ^ Data format version. Currently 3.
      , rncOptions :: !Word8
      -- ^ bit 0 - uses password
      , rncEncryptionSalt :: !ByteString
      -- ^ iff option includes "uses password"
      , rncHMACSalt :: !ByteString
      -- ^ iff options includes "uses password"
      , rncIV :: !ByteString
      -- ^ The initialisation vector
      -- The ciphertext is variable and encrypted in CBC mode
      , rncHMAC :: (ByteString -> ByteString)
      -- ^ The HMAC (32 bytes). This field is a continuation
      -- as the HMAC is at the end of the file.
      }

instance Show RNCryptorHeader where
  show = C8.unpack . renderRNCryptorHeader

instance Arbitrary RNCryptorHeader where
  arbitrary = do
    let version = toEnum 3
    let options = toEnum 1
    eSalt    <- C8.pack <$> vector saltSize
    iv       <- C8.pack <$> vector blockSize
    hmacSalt <- C8.pack <$> vector saltSize
    return RNCryptorHeader {
          rncVersion = version
        , rncOptions = options
        , rncEncryptionSalt = eSalt
        , rncHMACSalt = hmacSalt
        , rncIV = iv
        , rncHMAC = \uKey -> sha1PBKDF2 uKey hmacSalt 10000 32
        }

--------------------------------------------------------------------------------
saltSize :: Int
saltSize = 8

--------------------------------------------------------------------------------
blockSize :: Int
blockSize = 16

--------------------------------------------------------------------------------
randomSaltIO :: Int -> IO ByteString
randomSaltIO sz = C8.pack <$> forM [1 .. sz] (const $ randomRIO ('\NUL', '\255'))

--------------------------------------------------------------------------------
-- | Generates a new 'RNCryptorHeader', suitable for encryption.
newRNCryptorHeader :: ByteString -> IO RNCryptorHeader
newRNCryptorHeader userKey = do
  let version = toEnum 3
  let options = toEnum 1
  eSalt    <- randomSaltIO saltSize
  iv       <- randomSaltIO blockSize
  hmacSalt <- randomSaltIO saltSize
  return RNCryptorHeader {
        rncVersion = version
      , rncOptions = options
      , rncEncryptionSalt = eSalt
      , rncHMACSalt = hmacSalt
      , rncIV = iv
      , rncHMAC = const $ sha1PBKDF2 userKey hmacSalt 10000 32
      }

--------------------------------------------------------------------------------
-- | Concatenates this 'RNCryptorHeader' into a raw sequence of bytes, up to the
-- IV. This means you need to append the ciphertext plus the HMAC to finalise 
-- the encrypted file.
renderRNCryptorHeader :: RNCryptorHeader -> ByteString
renderRNCryptorHeader RNCryptorHeader{..} =
  rncVersion `cons` rncOptions `cons` (rncEncryptionSalt <> rncHMACSalt <> rncIV)

--------------------------------------------------------------------------------
-- A convenient datatype to avoid carrying around the AES cypher,
-- the encrypted key and so on and so forth.
data RNCryptorContext = RNCryptorContext {
        ctxHeader :: RNCryptorHeader
      , ctxCipher :: AES
      }

newtype UserInput = UI { unInput :: ByteString } deriving Show

instance Arbitrary UserInput where
  arbitrary = UI . C8.pack <$> arbitrary

--------------------------------------------------------------------------------
newRNCryptorContext :: ByteString -> RNCryptorHeader -> RNCryptorContext
newRNCryptorContext userKey hdr =
  let eKey = sha1PBKDF2 userKey (rncEncryptionSalt hdr) 10000 32
      cipher = initAES eKey
  in RNCryptorContext hdr cipher
