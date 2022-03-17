{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}

module Crypto.Signature
  ( PrivateKey,
    privateKeySize,
    generatePrivateKey,
    privateKeyToBytes,
    privateKeyFromBytes,
    privateToPublic,
    PublicKey,
    compressedPublicKeySize,
    compress,
    decompress,
    Signature (..),
    signatureSize,
    sign,
    verify,
  )
where

import Control.Monad (guard)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Internal (create)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Word (Word8)
import Foreign.C.Types (CBool (..), CSize (..))
import Foreign.ForeignPtr
  ( FinalizerPtr,
    ForeignPtr,
    newForeignPtr,
    withForeignPtr,
  )
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import GHC.IO (unsafePerformIO)
import Ourlude

foreign import ccall unsafe "signature_generate_private_key"
  c_signature_generate_private_key :: Ptr Word8 -> IO ()

foreign import ccall unsafe "signature_private_key_to_public_key"
  c_signature_private_key_to_public_key :: Ptr Word8 -> IO (Ptr CPublicKey)

foreign import ccall unsafe "&signature_free_public_key"
  c_signature_free_public_key :: FinalizerPtr CPublicKey

foreign import ccall unsafe "signature_public_key_compress"
  c_signature_public_key_compress :: Ptr CPublicKey -> Ptr Word8 -> IO ()

foreign import ccall unsafe "signature_sign"
  c_signature_sign :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> IO ()

foreign import ccall unsafe "signature_verify"
  c_signature_verify :: Ptr CPublicKey -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CBool

foreign import ccall unsafe "signature_public_key_decompress"
  c_signature_public_key_decompress :: Ptr Word8 -> CSize -> IO (Ptr CPublicKey)

-- | Represents a private key, which allows us to sign new messages.
--
-- Each private key is associated with a corresponding public key. The public
-- key allows verifying the signatures produced with the private key.
newtype PrivateKey = PrivateKey {bytes :: ByteString} deriving (Show)

-- | The number of bytes used to encode a private key.
privateKeySize :: Int
privateKeySize = 32

-- | Generate a new private key, randomly.
--
-- This uses the secure randomness provided by the Operating System. Because
-- different calls to the function will return different results, this
-- functionality is wrapped in IO.
generatePrivateKey :: IO PrivateKey
generatePrivateKey =
  create privateKeySize c_signature_generate_private_key |> fmap PrivateKey

-- | Serialize a private key to bytes.
privateKeyToBytes :: PrivateKey -> ByteString
privateKeyToBytes priv = priv.bytes

-- | Deserialize a private key from bytes, potentially failing.
privateKeyFromBytes :: ByteString -> Maybe PrivateKey
privateKeyFromBytes bs = guard (BS.length bs == privateKeySize) >> Just (PrivateKey bs)

-- | Derive the public key associated with this private key.
privateToPublic :: PrivateKey -> PublicKey
privateToPublic priv = privToPubIO priv |> unsafePerformIO |> PublicKey
  where
    privToPubIO :: PrivateKey -> IO (ForeignPtr CPublicKey)
    privToPubIO (PrivateKey privBS) =
      unsafeUseAsCStringLen privBS
        <| \(privPtr, _) -> do
          pubPtr <- c_signature_private_key_to_public_key (castPtr privPtr)
          newForeignPtr c_signature_free_public_key pubPtr

-- An opaque type used to represent whatever is behind the pointers in Rust land.
data CPublicKey

-- | Represents a public key, used to verify signatures.
--
-- This public key has a corresponding private key, without which signatures
-- can't be created. This public key can verify those signatures, and can
-- safely be shared without revealing the private key.
--
-- For serialization, a public key is compressed, encoding it in a more
-- succint string of bytes.
newtype PublicKey = PublicKey (ForeignPtr CPublicKey)

-- | The number of bytes in the compression of a public key.
compressedPublicKeySize :: Int
compressedPublicKeySize = 32

-- | Compress a public key into a more succint representation as bytes.
compress :: PublicKey -> ByteString
compress pub = unsafePerformIO (compressIO pub)
  where
    compressIO :: PublicKey -> IO ByteString
    compressIO (PublicKey pubFP) =
      create compressedPublicKeySize <| \bsPtr ->
        withForeignPtr pubFP <| \p ->
          c_signature_public_key_compress p bsPtr

-- | Decompress a string of bytes into a public key, potentially failing.
decompress :: ByteString -> Maybe PublicKey
decompress bytes = do
  guard (BS.length bytes == compressedPublicKeySize)
  decompressIO bytes |> unsafePerformIO |> fmap PublicKey
  where
    decompressIO :: ByteString -> IO (Maybe (ForeignPtr CPublicKey))
    decompressIO bytes =
      unsafeUseAsCStringLen bytes <| \(bytesPtr, bytesLen) -> do
        pubPtr <- c_signature_public_key_decompress (castPtr bytesPtr) (fromIntegral bytesLen)
        if pubPtr == nullPtr
          then return Nothing
          else Just <$> newForeignPtr c_signature_free_public_key pubPtr

-- | Represents a signature.
--
-- A signature is produced by a private key over a given message.
-- The signature can be verified to be valid for that message, using
-- the corresponding private key. If the message changes, or the wrong public
-- key is used, the signature will fail to verify.
--
-- A signature is just 64 bytes. We allow an arbitrary bytestring as a
-- signature, but any bytestring of the wrong length will always fail to
-- verify as a signature.
newtype Signature = Signature {bytes :: ByteString} deriving (Show)

-- | The number of bytes in a signature.
signatureSize :: Int
signatureSize = 64

-- | Sign a message, using a private key.
sign :: PrivateKey -> ByteString -> Signature
sign priv messageBS = signIO priv messageBS |> unsafePerformIO |> Signature
  where
    signIO :: PrivateKey -> ByteString -> IO ByteString
    signIO priv messageBS =
      create signatureSize <| \sigPtr ->
        unsafeUseAsCStringLen priv.bytes <| \(privPtr, _) ->
          unsafeUseAsCStringLen messageBS <| \(messagePtr, messageLen) ->
            c_signature_sign (castPtr privPtr) (castPtr messagePtr) (fromIntegral messageLen) sigPtr

-- | Verify a signature over a message, using a public key.
verify :: PublicKey -> ByteString -> Signature -> Bool
verify pub messageBS sig = lengthValid && signatureVerifies
  where
    lengthValid = BS.length sig.bytes == signatureSize
    signatureVerifies = verifyIO pub messageBS sig |> unsafePerformIO |> (== 1)

    verifyIO :: PublicKey -> ByteString -> Signature -> IO CBool
    verifyIO (PublicKey pubFP) messageBS sig =
      withForeignPtr pubFP <| \pubPtr ->
        unsafeUseAsCStringLen messageBS <| \(messagePtr, messageLen) ->
          unsafeUseAsCStringLen sig.bytes <| \(sigPtr, _) ->
            c_signature_verify pubPtr (castPtr messagePtr) (fromIntegral messageLen) (castPtr sigPtr)
