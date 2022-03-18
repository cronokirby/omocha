{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}

module Crypto.Work
  ( ProofOfWork (..),
    proofOfWorkSize,
    checkProofOfWork,
    tryProofOfWork,
    makeProofOfWork,
  )
where

import Data.ByteString (ByteString)
import Data.ByteString.Internal (create)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Word (Word8)
import Foreign.C.Types (CBool (..), CSize (..))
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import GHC.IO (unsafePerformIO)
import Ourlude

foreign import ccall unsafe "proof_of_work_check"
  c_proof_of_work_check :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CBool

foreign import ccall unsafe "proof_of_work_try"
  c_proof_of_work_try :: Ptr Word8 -> CSize -> CSize -> Ptr Word8 -> IO CBool

foreign import ccall unsafe "proof_of_work_make"
  c_proof_of_work_make :: Ptr Word8 -> CSize -> Ptr Word8 -> IO ()

-- | Represents a proof of work, over some context.
--
-- This proof should be difficult to create, but relatively quick to verify.
data ProofOfWork = ProofOfWork {bytes :: ByteString}

-- | The number of bytes in a proof of work.
proofOfWorkSize :: Int
proofOfWorkSize = 48

-- | Check that a proof of work is valid over a certain context.
checkProofOfWork :: ByteString -> ProofOfWork -> Bool
checkProofOfWork contextBS pow = checkProofOfWorkIO contextBS pow |> unsafePerformIO |> (== 1)
  where
    checkProofOfWorkIO :: ByteString -> ProofOfWork -> IO CBool
    checkProofOfWorkIO contextBS pow =
      unsafeUseAsCStringLen contextBS <| \(contextPtr, contextLen) ->
        unsafeUseAsCStringLen pow.bytes <| \(powPtr, _) ->
          c_proof_of_work_check (castPtr contextPtr) (fromIntegral contextLen) (castPtr powPtr)

-- | Try creating a proof of work, with a certain number of tries.
--
-- The reason this exists is to allow periodically checking the head
-- of the chain, allowing us to stop working on a stale head.
tryProofOfWork :: Int -> ByteString -> IO (Maybe ProofOfWork)
tryProofOfWork = undefined

-- | Create a proof of work, using as many tries as necessary.
makeProofOfWork :: ByteString -> IO ProofOfWork
makeProofOfWork contextBS = makeProofOfWorkIO contextBS |> fmap ProofOfWork
  where
    makeProofOfWorkIO :: ByteString -> IO ByteString
    makeProofOfWorkIO contextBS =
      create proofOfWorkSize <| \powPtr ->
        unsafeUseAsCStringLen contextBS <| \(contextPtr, contextLen) ->
          c_proof_of_work_make (castPtr contextPtr) (fromIntegral contextLen) powPtr
