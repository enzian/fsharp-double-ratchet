module MessageTests

open Xunit
open Signal.Protocol.Messages
open System.Security.Cryptography
open Signal.Protocol.Endpoints
open FsUnit.Xunit
open FsUnit.CustomMatchers

[<Fact>]
let ``When Alice initiates a session key with Bob by using one of Bobs One-Time-Prekeys`` () =
    let aliceIdentityKey = ECDiffieHellman.Create()
    let aliceIdentityKeyPem = aliceIdentityKey.ExportSubjectPublicKeyInfoPem().ToCharArray()
    let aliceEphemeralKey = ECDiffieHellman.Create()
    let aliceEphemeralPem = aliceEphemeralKey.ExportSubjectPublicKeyInfoPem().ToCharArray()

    let sha = SHA256.Create();

    let bobIdentityKey = ECDiffieHellman.Create()
    let bobEphemeralKey = ECDiffieHellman.Create()
    let bobPrekey = ECDiffieHellman.Create()
    let bobPrekeyHash = sha.ComputeHash(bobPrekey.PublicKey.ExportSubjectPublicKeyInfo())

    let initMessage = {
        SenderIdentityKey = aliceIdentityKeyPem
        SenderEphemeralKey = aliceEphemeralPem 
        OTPKHash = bobPrekeyHash
        // Header = [|0uy|]
        // CipherMessage = [|1uy|]
    }

    let endpoint : Endpoint = {
        IdentityKey = bobIdentityKey
        EphemeralKey = bobEphemeralKey
        OneTimePrekeys = Map.ofSeq [bobPrekeyHash, bobPrekey]
    }

    match initiateSession endpoint initMessage with
    | Ok (postInitEp, ratchet) ->
        postInitEp.OneTimePrekeys |> should be Empty
    | Error _ -> Assert.Fail "session initialization should have succeeded"
