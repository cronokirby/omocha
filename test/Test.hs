{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Crypto.Signature as Sig
import Ourlude
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain allTests

allTests :: TestTree
allTests = testGroup "Tests" [unitTests]

unitTests :: TestTree
unitTests = testGroup "Unit" [signatureTests]

signatureTests :: TestTree
signatureTests =
  testGroup
    "Crypto.Signature"
    [ testSignatureVerification
    ]

testSignatureVerification =
  testCase "testSignatureVerification" <| do
    priv <- Sig.generatePrivateKey
    let pub = Sig.privateToPublic priv
        msg = "msg"
        sig = Sig.sign priv msg
    Sig.verify pub msg sig @=? True
