module Crypto.Work
  ( ProofOfWork (..),
    proofOfWorkSize,
    checkProofOfWork,
    tryProofOfWork,
    makeProofOfWork,
  )
where

import Data.ByteString (ByteString)
import Ourlude

-- | Represents a proof of work, over some context.
--
-- This proof should be difficult to create, but relatively quick to verify.
data ProofOfWork = ProofOfWork {bytes :: ByteString}

-- | The number of bytes in a proof of work.
proofOfWorkSize :: Int
proofOfWorkSize = undefined

-- | Check that a proof of work is valid over a certain context.
checkProofOfWork :: ByteString -> ProofOfWork -> Bool
checkProofOfWork = undefined

-- | Try creating a proof of work, with a certain number of tries.
tryProofOfWork :: Int -> ByteString -> IO (Maybe ProofOfWork)
tryProofOfWork = undefined

-- | Create a proof of work, using as many tries as necessary.
makeProofOfWork :: ByteString -> IO ProofOfWork
makeProofOfWork = undefined
