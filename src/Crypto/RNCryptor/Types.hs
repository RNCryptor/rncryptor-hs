{-# LANGUAGE RecordWildCards #-}
module Crypto.RNCryptor.Types
     ( RNCryptorException(..)
     , RNCryptorHeader(..)
     , RNCryptorContext(ctxHeader, ctxHMACCtx, ctxCipher)
     , UserInput(..)
     , newRNCryptorContext
     , newRNCryptorHeader
     , renderRNCryptorHeader
     , makeHMAC
     , blockSize
     ) where

import           Control.Applicative
import           Control.Monad
import           Crypto.Cipher.AES      (AES256)
import           Crypto.Cipher.Types    (Cipher(..))
import           Crypto.Error           (CryptoFailable(..))
import           Control.Exception      (Exception)
import           Crypto.Hash            (Digest(..))
import           Crypto.Hash.Algorithms (SHA1(..), SHA256(..))
import           Crypto.Hash.IO         (HashAlgorithm(..))
import           Crypto.KDF.PBKDF2      (generate, prfHMAC, Parameters(..))
import           Crypto.MAC.HMAC        (HMAC(..), Context, initialize, hmac)
import           Data.ByteArray         (ByteArray, convert)
import           Data.ByteString        (cons, ByteString)
import qualified Data.ByteString.Char8 as C8
import           Data.Monoid
import           Data.Typeable
import           Data.Word
import           System.Random
import           Test.QuickCheck        (Arbitrary(..), vector)


data RNCryptorException =
  InvalidHMACException !ByteString !ByteString
  -- ^ HMAC validation failed. First parameter is the untrusted hmac, the
  -- second the computed one.
  deriving Typeable

instance Show RNCryptorException where
  show (InvalidHMACException untrusted computed) = "InvalidHMACException: Untrusted HMAC was " <> C8.unpack untrusted
                                                 <> ", but the computed one is " <> C8.unpack computed <> "."

instance Exception RNCryptorException


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
makeKey :: ByteString -> ByteString -> ByteString
makeKey = generate (prfHMAC SHA1) (Parameters 10000 32)

--------------------------------------------------------------------------------
makeHMAC :: ByteString -> ByteString -> ByteString -> ByteString
makeHMAC hmacSalt userKey secret =
  let key        = makeKey userKey hmacSalt
      hmacSha256 = hmac key secret
  in
      convert (hmacSha256 :: HMAC SHA256)

--------------------------------------------------------------------------------
-- | Generates a new 'RNCryptorHeader', suitable for encryption.
newRNCryptorHeader :: IO RNCryptorHeader
newRNCryptorHeader = do
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
        ctxHeader  :: RNCryptorHeader
      , ctxCipher  :: AES256
      , ctxHMACCtx :: Context SHA256
      }

newtype UserInput = UI { unInput :: ByteString } deriving Show

instance Arbitrary UserInput where
  arbitrary = UI . C8.pack <$> arbitrary

--------------------------------------------------------------------------------
cipherInitNoError :: ByteString -> AES256
cipherInitNoError k = case cipherInit k of
  CryptoPassed a -> a
  CryptoFailed e -> error ("cipherInitNoError: " <> show e)

--------------------------------------------------------------------------------
newRNCryptorContext :: ByteString -> RNCryptorHeader -> RNCryptorContext
newRNCryptorContext userKey hdr =
  let hmacSalt = rncHMACSalt hdr
      hmacKey  = makeKey userKey hmacSalt
      hmacCtx  = initialize hmacKey::Context SHA256
      encKey   = makeKey userKey $ rncEncryptionSalt hdr
      cipher   = cipherInitNoError encKey
  in RNCryptorContext hdr cipher hmacCtx
