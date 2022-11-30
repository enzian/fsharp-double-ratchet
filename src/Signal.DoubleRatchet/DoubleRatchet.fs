namespace Signal.DoubleRatchet

open System.Security.Cryptography

module DoubleRatchet =

    let commonAes = Aes.Create()
    commonAes.GenerateIV()

    let MAX_SKIP = 1000u

    exception SkipRangeError of string

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

    let EncryptMessage state plaintext =
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

        let DHRatchet (dhs: byte array) state  =
            let senderPubKey = ECDiffieHellman.Create()
            senderPubKey.ImportSubjectPublicKeyInfo(dhs) |> ignore
            let DHr = senderPubKey.PublicKey

            let state =
                { state with
                    PN = state.Ns
                    Ns = 0u
                    Nr = 0u
                    DHr = Some DHr }

            let dh = state.DHs.DeriveKeyMaterial(state.DHr.Value)
            let RK, CKr = kdf_rk state.RK dh
            let RK, CKs = kdf_rk RK dh

            { state with
                RK = RK
                CKr = Some CKr
                CKs = CKs }

        let skipMessageKeys until state =
            if (state.Nr + MAX_SKIP) < until then
                raise (SkipRangeError "cannot skip this many messages")

            match state.CKr with
            | Some ckr ->
                let dhr = state.DHr.Value.ExportSubjectPublicKeyInfo()
                let mutable CKr = ckr

                let newlySkippedMks =
                    [ 

                      for i in [ state.Nr .. (until - 1u) ] do
                          let ckr, mk = kdf_ck CKr
                          CKr <- ckr
                          (dhr, i), mk ]

                { state with
                    CKr = Some CKr;
                    Nr = until - 1u;
                    MKSKIPPED =
                        newlySkippedMks
                        |> Seq.fold (fun acc (key, value) -> acc.Add(key, value)) state.MKSKIPPED; }
            | None -> state

        let state =
            match (state.DHr, state.CKr, headers.DHs) with
            // got a sender pub key but does not have one yet
            | (None, None, dhs) ->
                printfn "never got a Public Key, running DH ratchet"
                state |> DHRatchet dhs
            // got sender public key but it does not match the one we have
            | (Some dhr, Some ckr, dhs) when not (dhr.ExportSubjectPublicKeyInfo() = dhs) ->
                printfn "got new pub key, running DH ratchet"
                // Skip all messages until header.Ns and run a new DH ratchet step
                state |> skipMessageKeys headers.Ns |> DHRatchet dhs
            // perform a normal key exchange
            | (Some _, Some _, _) ->
                printfn "Normal chain key ratchet"
                state

        // if the message sequence number in the header if further ahead messages in between must be skipped
        let state =
            if state.Nr < headers.Ns then
                let state = state |> skipMessageKeys headers.Ns
                state
            else
                state
        
        let CKr, mk = kdf_ck state.CKr.Value
        
        use aesAlg = Aes.Create()
        aesAlg.IV <- commonAes.IV
        aesAlg.Key <- mk
        let clearText = aesAlg.DecryptCbc(cypherText, aesAlg.IV)

        ({ state with
            CKr = Some CKr
            Nr = state.Nr + 1u },
         clearText)
