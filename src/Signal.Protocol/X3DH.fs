namespace Signal.Protocol

module X3DH =
    open System.Security.Cryptography

    let DeriveKey input =
        HKDF.DeriveKey(HashAlgorithmName.SHA512, input, 32, [| for i in 0..64 -> 0uy |])

    exception SignaturValidationError of string

    let SenderKey
        (ourIdKey: ECDiffieHellman)
        (ourEphemeralKey: ECDiffieHellman)
        (theirIdKey: ECDiffieHellmanPublicKey)
        (their_prekey: ECDiffieHellmanPublicKey)
        (prekeySig: byte array)
        =
        let ecDsa = ECDsa.Create(theirIdKey.ExportParameters())
        let prekeyBytes = their_prekey.ExportSubjectPublicKeyInfo()

        if not (ecDsa.VerifyData(prekeyBytes, prekeySig, HashAlgorithmName.SHA512)) then
            raise (SignaturValidationError "prekey signatures were invalid")

        let dh1 = ourIdKey.DeriveKeyMaterial(their_prekey)
        let dh2 = ourEphemeralKey.DeriveKeyMaterial(theirIdKey)
        let dh3 = ourEphemeralKey.DeriveKeyMaterial(their_prekey)
        DeriveKey([ dh1; dh2; dh3 ] |> Array.concat)

    let ReceiverKey
        (ourIdKey: ECDiffieHellman)
        (ourEphemeralKey: ECDiffieHellman)
        (theirIdKey: ECDiffieHellmanPublicKey)
        (theirEphemeralKey: ECDiffieHellmanPublicKey)
        =
        let dh1 = ourEphemeralKey.DeriveKeyMaterial(theirIdKey)
        let dh2 = ourIdKey.DeriveKeyMaterial(theirEphemeralKey)
        let dh3 = ourEphemeralKey.DeriveKeyMaterial(theirEphemeralKey)
        DeriveKey([ dh1; dh2; dh3 ] |> Array.concat)
