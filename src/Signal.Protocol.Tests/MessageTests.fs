module MessageTests

open Xunit
open Signal.Protocol.Messages
open System.Security.Cryptography
open Signal.Protocol.Endpoints
open FsUnit.Xunit
open FsUnit.CustomMatchers
open Signal.Protocol.DoubleRatchet
open System.Text

let CreateKeyMaterial =
    let identityKey = ECDiffieHellman.Create()
    let ephemeralKey = ECDiffieHellman.Create()

    (identityKey, ephemeralKey)

let CreateKeyMaterialWithPem =
    let identityKey, ephemeralKey = CreateKeyMaterial
    let idKeyPem = identityKey.ExportSubjectPublicKeyInfoPem().ToCharArray()
    let ephemeralKeyPem = ephemeralKey.ExportSubjectPublicKeyInfoPem().ToCharArray()

    (identityKey, idKeyPem, ephemeralKey, ephemeralKeyPem)

let CreateSignedPrekey (identityKey: ECDiffieHellman) =
    let sha = SHA256.Create()
    let ecDsab = ECDsa.Create(identityKey.ExportParameters(true))

    let prekey = ECDiffieHellman.Create()
    let publicKeyInfo = prekey.PublicKey.ExportSubjectPublicKeyInfo()
    let prekeyHash = sha.ComputeHash(publicKeyInfo)
    let prekeySignature = ecDsab.SignData(publicKeyInfo, HashAlgorithmName.SHA512)

    (prekey, prekeyHash, prekeySignature)

[<Fact>]
let ``When Alice initiates a session key with Bob by using one of Bobs One-Time-Prekeys`` () =
    let _, aliceIdentityKeyPem, _, aliceEphemeralPem = CreateKeyMaterialWithPem

    let bobIdentityKey, _ = CreateKeyMaterial
    let (prekey, _, _) = CreateSignedPrekey bobIdentityKey 
    let (otpk, otHash, _) = CreateSignedPrekey bobIdentityKey

    let initMessage =
        { SenderIdentityKey = aliceIdentityKeyPem
          SenderEphemeralKey = aliceEphemeralPem
          OTPKHash = otHash }

    let endpoint: Endpoint =
        { IdentityKey = bobIdentityKey
          EphemeralKey = prekey
          OneTimePrekeys = Map.ofSeq [ otHash, otpk ] }

    match handleInitMessage endpoint initMessage with
    | Ok (postInitEp, _) -> postInitEp.OneTimePrekeys |> should be Empty
    | Error _ -> Assert.Fail "session initialization should have succeeded"

[<Fact>]
let ``Alice and Bob will agree on the same root key after performing a X3DH key exchange`` () =
    let aliceIdentityKey, aliceEphemeralKey = CreateKeyMaterial

    let bobIdentityKey, _ = CreateKeyMaterial
    let (prekey, _, signature) = CreateSignedPrekey bobIdentityKey
    let (otpk, othash, _) = CreateSignedPrekey bobIdentityKey


    let bobEndpoint: Endpoint =
        { IdentityKey = bobIdentityKey
          EphemeralKey = prekey
          OneTimePrekeys = Map.ofSeq [ othash, otpk ] }

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
            othash
            prekey.PublicKey
            otpk.PublicKey

    match handleInitMessage bobEndpoint initMessage with
    | Ok (_, bobRatchet) -> aliceRatchet.RK |> should equal bobRatchet.RK // Bob and alice have derrived the same Root key!
    | Error msg -> failwithf "Receiver failed to initialize the session: %s" msg

[<Fact>]
let ``Messages can be sent from Alice to Bob and v.v.`` () =
    let _, aliceEphemeralKey = CreateKeyMaterial
    let _, bobEphemeralKey = CreateKeyMaterial

    let psk = [|0uy..31uy|]
    let ad = "test-msg"

    let bobRatchet = ratchetInit psk bobEphemeralKey None
    let aliceRatchet = ratchetInit psk aliceEphemeralKey (Some bobRatchet.DHs.PublicKey)

    let encryptToMessage ratchet msg = 
        let ratchet, ciphertext, header = EncryptMessage ad ratchet msg
        ({
            Header =  header
            CipherText = ciphertext
        },
        ratchet)

    let clearText = Encoding.UTF8.GetBytes "test"
    
    let msg, aliceRatchet = encryptToMessage aliceRatchet clearText
    let bobRatchet, clearText = DecryptMessage ad bobRatchet msg.Header msg.CipherText

    clearText |> should equal clearText