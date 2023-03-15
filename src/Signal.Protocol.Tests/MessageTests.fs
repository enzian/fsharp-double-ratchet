module MessageTests

open Xunit
open Signal.Protocol.Messages
open System.Security.Cryptography
open Signal.Protocol.Endpoints
open Signal.Protocol
open FsUnit.Xunit
open FsUnit.CustomMatchers

[<Fact>]
let ``When Alice initiates a session key with Bob by using one of Bobs One-Time-Prekeys`` () =
    let aliceIdentityKey = ECDiffieHellman.Create()

    let aliceIdentityKeyPem =
        aliceIdentityKey.ExportSubjectPublicKeyInfoPem().ToCharArray()

    let aliceEphemeralKey = ECDiffieHellman.Create()

    let aliceEphemeralPem =
        aliceEphemeralKey.ExportSubjectPublicKeyInfoPem().ToCharArray()

    let sha = SHA256.Create()

    let bobIdentityKey = ECDiffieHellman.Create()
    let bobEphemeralKey = ECDiffieHellman.Create()
    let bobPrekey = ECDiffieHellman.Create()

    let bobPrekeyHash =
        sha.ComputeHash(bobPrekey.PublicKey.ExportSubjectPublicKeyInfo())

    let initMessage =
        { SenderIdentityKey = aliceIdentityKeyPem
          SenderEphemeralKey = aliceEphemeralPem
          OTPKHash = bobPrekeyHash }

    let endpoint: Endpoint =
        { IdentityKey = bobIdentityKey
          EphemeralKey = bobEphemeralKey
          OneTimePrekeys = Map.ofSeq [ bobPrekeyHash, bobPrekey ] }

    match handleInitMessage endpoint initMessage with
    | Ok (postInitEp, _) -> postInitEp.OneTimePrekeys |> should be Empty
    | Error _ -> Assert.Fail "session initialization should have succeeded"



[<Fact>]
let ``Alice and Bob will agree on the same root key`` () =
    let sha = SHA256.Create()
    let aliceIdentityKey = ECDiffieHellman.Create()
    let aliceEphemeralKey = ECDiffieHellman.Create()
    let alicePrekey = ECDiffieHellman.Create()

    let alicePrekeyHash =
        sha.ComputeHash(alicePrekey.PublicKey.ExportSubjectPublicKeyInfo())

    let bobIdentityKey = ECDiffieHellman.Create()
    let bobEphemeralKey = ECDiffieHellman.Create()
    let bobPrekey = ECDiffieHellman.Create()

    let bobPrekeyHash =
        sha.ComputeHash(bobPrekey.PublicKey.ExportSubjectPublicKeyInfo())

    let ecDsab = ECDsa.Create(bobIdentityKey.ExportParameters(true))

    let bobPrekeySignature =
        ecDsab.SignData(bobPrekey.PublicKey.ExportSubjectPublicKeyInfo(), HashAlgorithmName.SHA512)

    let bobEndpoint: Endpoint =
        { IdentityKey = bobIdentityKey
          EphemeralKey = bobEphemeralKey
          OneTimePrekeys = Map.ofSeq [ bobPrekeyHash, bobPrekey ] }

    let aliceEndpoint: Endpoint =
        { IdentityKey = aliceIdentityKey
          EphemeralKey = aliceEphemeralKey
          OneTimePrekeys = Map.ofSeq [ alicePrekeyHash, alicePrekey ] }

    let (initMessage, aliceRatchet) =
        createInitMessage
            aliceEndpoint
            bobIdentityKey.PublicKey
            bobPrekey.PublicKey
            bobPrekeySignature
            bobPrekeyHash
            bobEphemeralKey.PublicKey

    match handleInitMessage bobEndpoint initMessage with
    | Ok (_, bobRatchet) -> aliceRatchet.RK |> should equal bobRatchet.RK
    | Error msg -> failwithf "Failed to initiate the session in bob's side: %s" msg
