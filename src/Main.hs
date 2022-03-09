{-# LANGUAGE OverloadedStrings #-}
module Main where

import Crypto.Signature
import Ourlude

main :: IO ()
main = do
  priv <- generatePrivateKey
  let pub = privateToPublic priv
      sig1 = sign priv "foo"
  print (verify pub "foo" sig1)
  print (verify pub "foo2" sig1)
