{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}

module Crypto.Signature where

import Data.ByteString
import Data.ByteString.Builder
import Data.ByteString.Internal
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Word
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import GHC.IO (unsafePerformIO)
import Ourlude

privateKeySize :: Int
privateKeySize = 32

foreign import ccall unsafe "signature_generate_private_key"
  c_signature_generate_private_key :: Ptr Word8 -> IO ()

foreign import ccall unsafe "signature_private_key_to_public_key"
  c_signature_private_key_to_public_key :: Ptr Word8 -> IO (Ptr CPublicKey)

foreign import ccall unsafe "&signature_free_public_key"
  c_signature_free_public_key :: FinalizerPtr CPublicKey

foreign import ccall unsafe "signature_public_key_compress"
  c_signature_public_key_compress :: Ptr CPublicKey -> Ptr Word8 -> IO ()

newtype PrivateKey = PrivateKey ByteString deriving (Show)

generatePrivateKey :: IO PrivateKey
generatePrivateKey =
  create privateKeySize c_signature_generate_private_key |> fmap PrivateKey

privateToPublic :: PrivateKey -> PublicKey
privateToPublic (PrivateKey bs) =
  PublicKey <| unsafePerformIO
    <| unsafeUseAsCStringLen bs
    <| \(privPtr, _) -> do
      pubPtr <- c_signature_private_key_to_public_key (castPtr privPtr)
      newForeignPtr c_signature_free_public_key pubPtr

data CPublicKey

newtype PublicKey = PublicKey (ForeignPtr CPublicKey)

newtype CompressedPublicKey = CompressedPublicKey {bytes :: ByteString} deriving (Show)

compressedPublicKeySize :: Int
compressedPublicKeySize = 32

compress :: PublicKey -> CompressedPublicKey
compress (PublicKey fp) =
  unsafePerformIO <| do
    bs <- create compressedPublicKeySize (\bsPtr -> withForeignPtr fp (\p -> c_signature_public_key_compress p bsPtr))
    return (CompressedPublicKey bs)
