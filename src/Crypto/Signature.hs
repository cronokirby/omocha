{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}

module Crypto.Signature where

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

newtype PrivateKey = PrivateKey {bytes :: ByteString} deriving (Show)

privateKeySize :: Int
privateKeySize = 32

generatePrivateKey :: IO PrivateKey
generatePrivateKey =
  create privateKeySize c_signature_generate_private_key |> fmap PrivateKey

privateKeyToBytes :: PrivateKey -> ByteString
privateKeyToBytes priv = priv.bytes

privateKeyFromBytes :: ByteString -> Maybe PrivateKey
privateKeyFromBytes bs = guard (BS.length bs == privateKeySize) >> Just (PrivateKey bs)

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

compressedPublicKeySize :: Int
compressedPublicKeySize = 32

compress :: PublicKey -> ByteString
compress pub = unsafePerformIO (compressIO pub)
  where
    compressIO :: PublicKey -> IO ByteString
    compressIO (PublicKey pubFP) =
      create compressedPublicKeySize <| \bsPtr ->
        withForeignPtr pubFP <| \p ->
          c_signature_public_key_compress p bsPtr

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
