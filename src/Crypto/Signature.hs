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

foreign import ccall unsafe "signature_sign"
  c_signature_sign :: Ptr Word8 -> Ptr Word8 -> CInt -> Ptr Word8 -> IO ()

foreign import ccall unsafe "signature_verify"
  c_signature_verify :: Ptr CPublicKey -> Ptr Word8 -> CInt -> Ptr Word8 -> IO CBool

foreign import ccall unsafe "signature_public_key_decompress"
  c_signature_public_key_decompress :: Ptr Word8 -> CInt -> IO (Ptr CPublicKey)

newtype PrivateKey = PrivateKey {bytes :: ByteString} deriving (Show)

generatePrivateKey :: IO PrivateKey
generatePrivateKey =
  create privateKeySize c_signature_generate_private_key |> fmap PrivateKey

privateToPublic :: PrivateKey -> PublicKey
privateToPublic priv = privToPubIO priv |> unsafePerformIO |> PublicKey
  where
    privToPubIO :: PrivateKey -> IO (ForeignPtr CPublicKey)
    privToPubIO (PrivateKey privBS) =
      unsafeUseAsCStringLen privBS
        <| \(privPtr, _) -> do
          pubPtr <- c_signature_private_key_to_public_key (castPtr privPtr)
          newForeignPtr c_signature_free_public_key pubPtr

data CPublicKey

newtype PublicKey = PublicKey (ForeignPtr CPublicKey)

newtype CompressedPublicKey = CompressedPublicKey {bytes :: ByteString} deriving (Show)

compressedPublicKeySize :: Int
compressedPublicKeySize = 32

compress :: PublicKey -> CompressedPublicKey
compress pub = unsafePerformIO (compressIO pub) |> CompressedPublicKey
  where
    compressIO :: PublicKey -> IO ByteString
    compressIO (PublicKey pubFP) =
      create compressedPublicKeySize <| \bsPtr ->
        withForeignPtr pubFP <| \p ->
          c_signature_public_key_compress p bsPtr

decompress :: ByteString -> Maybe PublicKey
decompress bytes = decompressIO bytes |> unsafePerformIO |> fmap PublicKey
  where
    decompressIO :: ByteString -> IO (Maybe (ForeignPtr CPublicKey))
    decompressIO bytes =
      unsafeUseAsCStringLen bytes <| \(bytesPtr, bytesLen) -> do
        pubPtr <- c_signature_public_key_decompress (castPtr bytesPtr) (fromIntegral bytesLen)
        if pubPtr == nullPtr
          then return Nothing
          else Just <$> newForeignPtr c_signature_free_public_key pubPtr

newtype Signature = Signature {bytes :: ByteString} deriving (Show)

signatureSize :: Int
signatureSize = 64

sign :: PrivateKey -> ByteString -> Signature
sign priv messageBS = signIO priv messageBS |> unsafePerformIO |> Signature
  where
    signIO :: PrivateKey -> ByteString -> IO ByteString
    signIO priv messageBS =
      create signatureSize <| \sigPtr ->
        unsafeUseAsCStringLen priv.bytes <| \(privPtr, _) ->
          unsafeUseAsCStringLen messageBS <| \(messagePtr, messageLen) ->
            c_signature_sign (castPtr privPtr) (castPtr messagePtr) (fromIntegral messageLen) sigPtr

verify :: PublicKey -> ByteString -> Signature -> Bool
verify pub messageBS sig = verifyIO pub messageBS sig |> unsafePerformIO |> (== 1)
  where
    verifyIO :: PublicKey -> ByteString -> Signature -> IO CBool
    verifyIO (PublicKey pubFP) messageBS sig =
      withForeignPtr pubFP <| \pubPtr ->
        unsafeUseAsCStringLen messageBS <| \(messagePtr, messageLen) ->
          unsafeUseAsCStringLen sig.bytes <| \(sigPtr, _) ->
            c_signature_verify pubPtr (castPtr messagePtr) (fromIntegral messageLen) (castPtr sigPtr)
