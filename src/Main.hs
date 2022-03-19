{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.Signature
import Crypto.Work (ProofOfWork (..), checkProofOfWork, makeProofOfWork, tryProofOfWork)
import Ourlude

main :: IO ()
main = do
  let context = "context"
  pow <- tryProofOfWork 10 context
  print (fmap (\x -> x.bytes) pow)
