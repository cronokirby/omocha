{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.Signature
import Crypto.Work (ProofOfWork (..), checkProofOfWork, makeProofOfWork)
import Ourlude

main :: IO ()
main = do
  let context = "context"
  pow <- makeProofOfWork context
  print (pow.bytes)
  print (checkProofOfWork context pow)
