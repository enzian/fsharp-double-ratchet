module MessageTests

open Xunit
open Signal.Protocol.Messages
open System.Security.Cryptography
open Signal.Protocol.Endpoints
open FsUnit.Xunit
open FsUnit.CustomMatchers

let CreateKeyMaterial =
    let identityKey = ECDiffieHellman.Create()
    let ephemeralKey = ECDiffieHellman.Create()

    (identityKey, ephemeralKey)

let CreateSignedPrekeys (identityKey: ECDiffieHellman) nofPrekeys =
    let sha = SHA256.Create()
    let ecDsab = ECDsa.Create(identityKey.ExportParameters(true))

    seq {
        for _ in 1..nofPrekeys ->
            let prekey = ECDiffieHellman.Create()
            let publicKeyInfo = prekey.PublicKey.ExportSubjectPublicKeyInfo()
            let prekeyHash = sha.ComputeHash(publicKeyInfo)
            let prekeySignature = ecDsab.SignData(publicKeyInfo, HashAlgorithmName.SHA512)

            (prekey, prekeyHash, prekeySignature)
    }

[<Fact>]
let ``When Alice initiates a session key with Bob by using one of Bobs One-Time-Prekeys`` () =
    let aliceIdentityKey, aliceEphemeralKey = CreateKeyMaterial

    let aliceIdentityKeyPem =
        aliceIdentityKey.ExportSubjectPublicKeyInfoPem().ToCharArray()

    let aliceEphemeralPem =
        aliceEphemeralKey.ExportSubjectPublicKeyInfoPem().ToCharArray()

    let bobIdentityKey, bobEphemeralKey = CreateKeyMaterial
    let bobPrekeys = CreateSignedPrekeys bobIdentityKey 1
    let (prekey, hash, _) = bobPrekeys |> Seq.exactlyOne

    let initMessage =
        { SenderIdentityKey = aliceIdentityKeyPem
          SenderEphemeralKey = aliceEphemeralPem
          OTPKHash = hash }

    let endpoint: Endpoint =
        { IdentityKey = bobIdentityKey
          EphemeralKey = bobEphemeralKey
          OneTimePrekeys = Map.ofSeq [ hash, prekey ] }

    match handleInitMessage endpoint initMessage with
    | Ok (postInitEp, _) -> postInitEp.OneTimePrekeys |> should be Empty
    | Error _ -> Assert.Fail "session initialization should have succeeded"


[<Fact>]
let ``Alice and Bob will agree on the same root key after performing a X3DH key exchange`` () =
    let aliceIdentityKey = ECDiffieHellman.Create()
    let aliceEphemeralKey = ECDiffieHellman.Create()

    let bobIdentityKey, bobEphemeralKey = CreateKeyMaterial
    let prekeys = CreateSignedPrekeys bobIdentityKey 1
    let (prekey, hash, signature) = prekeys |> Seq.exactlyOne

    let bobEndpoint: Endpoint =
        { IdentityKey = bobIdentityKey
          EphemeralKey = bobEphemeralKey
          OneTimePrekeys = Map.ofSeq [ hash, prekey ] }

    let aliceEndpoint: Endpoint =
        { IdentityKey = aliceIdentityKey
          EphemeralKey = aliceEphemeralKey
          OneTimePrekeys = Map.empty }

    let (initMessage, aliceRatchet) =
        createInitMessage
            aliceEndpoint
            bobIdentityKey.PublicKey
            prekey.PublicKey
            signature
            hash
            bobEphemeralKey.PublicKey

    match handleInitMessage bobEndpoint initMessage with
    | Ok (_, bobRatchet) -> aliceRatchet.RK |> should equal bobRatchet.RK
    | Error msg -> failwithf "Receiver failed to initialize the session: %s" msg
