module Main where

import Crypto.Signature
import Ourlude

main :: IO ()
main = do
  priv <- generatePrivateKey
  print priv
  let pub = privateToPublic priv
  print (compress pub)
