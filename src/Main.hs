{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import Crypto.Signature
import Ourlude

main :: IO ()
main = do
  priv <- generatePrivateKey
  let pub = privateToPublic priv
      sig1 = sign priv "foo"
      compressed = compress pub
  print compressed
  let Just pub2 = (decompress compressed)
  print (verify pub "foo" sig1)
  print (verify pub2 "foo" sig1)
  print (verify pub "foo2" sig1)
