
module Crypto.RNCryptor.Types 
     ( RNCryptorHeader(..)
     , RNCryptorContext(ctxHeader, ctxCipher)
     , newRNCryptorContext
     ) where

import Data.ByteString (ByteString)
import Data.Word
import Crypto.Cipher.AES
import Crypto.PBKDF.ByteString


data RNCryptorHeader = RNCryptorHeader {
        rncVersion :: Word8
      -- ^ Data format version. Currently 3.
      , rncOptions :: Word8
      -- ^ bit 0 - uses password
      , rncEncryptionSalt :: ByteString
      -- ^ iff option includes "uses password"
      , rncHMACSalt :: ByteString
      -- ^ iff options includes "uses password"
      , rncIV :: AESIV
      -- ^ The initialisation vector
      -- The ciphertext is variable and encrypted in CBC mode
      , rncHMAC :: (ByteString -> ByteString)
      -- ^ The HMAC (32 bytes). This field is a continuation
      -- as the HMAC is at the end of the file.
      }


--------------------------------------------------------------------------------
-- A convenient datatype to avoid carrying around the AES cypher,
-- the encrypted key and so on and so forth.
data RNCryptorContext = RNCryptorContext {
        ctxHeader :: RNCryptorHeader
      , ctxCipher :: AES
      }

--------------------------------------------------------------------------------
newRNCryptorContext :: ByteString -> RNCryptorHeader -> RNCryptorContext
newRNCryptorContext userKey hdr =
  let eKey = sha1PBKDF2 userKey (rncEncryptionSalt hdr) 10000 32
      cipher = initAES eKey
  in RNCryptorContext hdr cipher
