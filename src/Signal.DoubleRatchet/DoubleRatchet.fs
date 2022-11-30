namespace Signal.DoubleRatchet

open System.Security.Cryptography

module DoubleRatchet =

    let commonAes = Aes.Create()
    commonAes.GenerateIV();
    
    let kdf_rk (key: byte[]) dh_out =
        let kdf_out =
            HKDF.DeriveKey(HashAlgorithmName.SHA512, dh_out, (key.Length * 2), key)

        (kdf_out[0..31], kdf_out[32..63])

    let kdf_ck (key: byte[]) =
        let kdf_out = HKDF.DeriveKey(HashAlgorithmName.SHA512, key, (key.Length * 2))
        (kdf_out[0..31], kdf_out[32..63])

    type DoubleRatchetState =
        { DHs: ECDiffieHellman
          DHr: Option<ECDiffieHellmanPublicKey>
          RK: byte[]
          CKs: byte[]
          CKr: Option<byte[]>
          Ns: uint
          Nr: uint
          PN: uint
          MKSKIPPED: Map<(byte[] * uint), byte[]> }

    type MessageHeader = { DHs: byte[]; PN: uint; Ns: uint }

    let ratchetInit rootkey (keypair: ECDiffieHellman) (dh_public_key: ECDiffieHellmanPublicKey option) =
        match dh_public_key with
        | Some pub ->
            let dh_out = keypair.DeriveKeyMaterial(pub)
            let (rk, cks) = kdf_rk rootkey dh_out

            { DHs = keypair
              DHr = dh_public_key
              RK = rk
              CKs = cks
              CKr = None
              Ns = 0u
              Nr = 0u
              PN = 0u
              MKSKIPPED = Map [] }

        | None ->
            { DHs = keypair
              DHr = None
              RK = rootkey
              CKs = [||]
              CKr = None
              Ns = 0u
              Nr = 0u
              PN = 0u
              MKSKIPPED = Map [] }

    let EncryptMessage state plaintext ad =
        let (CKs, mk) = kdf_ck state.CKs

        let headers =
            { DHs = state.DHs.ExportSubjectPublicKeyInfo()
              PN = state.PN
              Ns = state.Ns }

        use aesAlg = Aes.Create()
        aesAlg.IV <- commonAes.IV
        aesAlg.Key <- mk

        let cypherText = aesAlg.EncryptCbc(plaintext, aesAlg.IV)

        ({ state with
            CKs = CKs
            Ns = (state.Ns + 1u) },
         cypherText,
         headers)

    let DecryptMessage state headers cypherText =
        let mutable state = state

        let (CKr, mk) =
            match state.CKr with
            | Some ckr -> kdf_ck ckr
            | None ->
                let keypair = ECDiffieHellman.Create()
                keypair.ImportSubjectPublicKeyInfo(headers.DHs) |> ignore

                state <- { state with DHr = Some keypair.PublicKey }
                let dh_out = state.DHs.DeriveKeyMaterial(keypair.PublicKey)
                let (rk, CKr) = kdf_rk state.RK dh_out
                let (rk, CKs) = kdf_rk rk dh_out
                state <- { state with RK = rk; CKr = Some CKr; CKs = CKs }
                kdf_ck CKr
            
        use aesAlg = Aes.Create()
        aesAlg.IV <- commonAes.IV
        aesAlg.Key <- mk
        let clearText = aesAlg.DecryptCbc(cypherText, aesAlg.IV)

        ({ state with
            CKr = Some CKr
            Nr = state.Nr + 1u },
         clearText)

