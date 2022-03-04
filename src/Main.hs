module Main where

import Ourlude

import Data.ByteString
import Data.ByteString.Internal
import Data.Word
import Foreign.C.Types
import Foreign.Ptr

foreign import ccall unsafe "init" c_init :: Ptr Word8 -> IO ()

initBS :: ByteString
initBS = unsafeCreate 5 c_init

main :: IO ()
main = initBS |> print
