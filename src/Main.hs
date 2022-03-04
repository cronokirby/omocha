module Main where

import Ourlude

import Foreign.C.Types

foreign import ccall "double" double :: CInt -> CInt

main :: IO ()
main = 3 |> double |> print
