module Main where

import Crypto.Signature
import Data.ByteString
import Data.ByteString.Builder
import Data.ByteString.Internal
import Data.Word
import Foreign.C.Types
import Foreign.Ptr
import Ourlude

main :: IO ()
main = do
  priv <- generatePrivateKey
  print priv
  let pub = privateToPublic priv
  print (compress pub)
