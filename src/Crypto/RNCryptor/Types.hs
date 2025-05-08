{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.RNCryptor.Types
     ( RNCryptorException(..)
     , RNCryptorHeader(..)
     , RNCryptorContext(ctxHeader, ctxHMACCtx, ctxCipher)
     , newRNCryptorContext
     , newRNCryptorHeader
     , newRNCryptorHeaderFrom
     , renderRNCryptorHeader
     , makeHMAC
     , blockSize
     -- * Type synonyms to make the API more descriptive
     , Password
     , HMAC
     , Salt
     , EncryptionKey
     , EncryptionSalt
     , HMACSalt
     , IV
     ) where

import              Control.Applicative
import              Control.Exception (Exception)
import              Control.Monad
import              Crypto.Cipher.AES (AES256)
import              Crypto.Cipher.Types (Cipher(..))
import              Crypto.Error (CryptoFailable(..))
import              Crypto.Hash (Digest(..))
import              Crypto.Hash.Algorithms (SHA1(..), SHA256(..))
import              Crypto.Hash.IO (HashAlgorithm(..))
#if FASTPBKDF2
import "fastpbkdf2" Crypto.KDF.PBKDF2 (fastpbkdf2_hmac_sha1)
#else
import "cryptonite" Crypto.KDF.PBKDF2
#endif
import              Crypto.MAC.HMAC (Context, initialize, hmac)
import qualified    Crypto.MAC.HMAC as Crypto
import              Data.ByteArray (ByteArray, convert)
import              Data.ByteString (cons, ByteString, unpack)
import qualified    Data.ByteString.Char8 as C8
import              Data.Monoid
import              Data.Typeable
import              Data.Word
import              System.Random
import              Test.QuickCheck (Arbitrary(..), vector)


data RNCryptorException =
    InvalidHMACException !ByteString !ByteString
    -- ^ HMAC validation failed. First parameter is the untrusted hmac, the
    -- second the computed one.
  | ImpossibleNoMoreBlocks !ByteString
  deriving (Typeable, Eq)

instance Show RNCryptorException where
  show (InvalidHMACException untrusted computed) =
    "InvalidHMACException: Untrusted HMAC was " <> show (unpack untrusted)
                                                <> ", but the computed one is " <> show (unpack computed) <> "."
  show (ImpossibleNoMoreBlocks l) = "No more blocks to stream (leftover: " <> showHex l

instance Exception RNCryptorException

type Password = ByteString
type HMAC = ByteString
type EncryptionKey = ByteString
type Salt = ByteString
type EncryptionSalt = Salt
type HMACSalt = Salt
type IV = ByteString

data RNCryptorHeader = RNCryptorHeader {
        rncVersion :: !Word8
      -- ^ Data format version. Currently 3.
      , rncOptions :: !Word8
      -- ^ bit 0 - uses password
      , rncEncryptionSalt :: !EncryptionSalt
      -- ^ iff option includes "uses password"
      , rncHMACSalt :: !HMACSalt
      -- ^ iff options includes "uses password"
      , rncIV :: !IV
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
#if FASTPBKDF2
makeKey input salt = fastpbkdf2_hmac_sha1 input salt 10000 32
#else
makeKey = generate (prfHMAC SHA1) (Parameters 10000 32)
#endif

--------------------------------------------------------------------------------
makeHMAC :: ByteString -> Password -> ByteString -> HMAC
makeHMAC hmacSalt userKey secret =
  let key        = makeKey userKey hmacSalt
      hmacSha256 = hmac key secret
  in
      convert (hmacSha256 :: Crypto.HMAC SHA256)

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
newRNCryptorHeaderFrom :: EncryptionSalt -> HMACSalt -> IV -> RNCryptorHeader
newRNCryptorHeaderFrom eSalt hmacSalt iv = do
  let version = toEnum 3
  let options = toEnum 1
  RNCryptorHeader {
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

--------------------------------------------------------------------------------
cipherInitNoError :: ByteString -> AES256
cipherInitNoError k = case cipherInit k of
  CryptoPassed a -> a
  CryptoFailed e -> error ("cipherInitNoError: " <> show e)

--------------------------------------------------------------------------------
newRNCryptorContext :: Password -> RNCryptorHeader -> RNCryptorContext
newRNCryptorContext userKey hdr =
  let hmacSalt = rncHMACSalt hdr
      hmacKey  = makeKey userKey hmacSalt
      hmacCtx  = initialize hmacKey
      encKey   = makeKey userKey $ rncEncryptionSalt hdr
      cipher   = cipherInitNoError encKey
  in RNCryptorContext hdr cipher (hmacCtx :: Context SHA256)
