namespace Signal.Protocol

module Messages =

    type SessionInitiationMsg =
        { SenderIdentityKey: char array
          SenderEphemeralKey: char array
          OTPKHash: byte array }

    type EstablishedSessionMessage =
        { Header: byte array
          CipherText: byte array }

    type ProtocolMessage =
        | Initialization of SessionInitiationMsg
        | EstablishedSession of EstablishedSessionMessage

module Endpoints =
    open System.Security.Cryptography
    open Messages
    open System

    type Endpoint =
        { IdentityKey: ECDiffieHellman
          EphemeralKey: ECDiffieHellman
          OneTimePrekeys: Map<byte array, ECDiffieHellman> }

    let createInitMessage (ourEndpoint : Endpoint) theirIdKey theirPrekey prekeySignature theirPrekeyHash theirEphemeralKey =
        let sk =
            X3DH.SenderKey ourEndpoint.IdentityKey ourEndpoint.EphemeralKey theirIdKey theirPrekey prekeySignature
        
        let receiverRatchet =
            DoubleRatchet.ratchetInit sk ourEndpoint.EphemeralKey (Some theirEphemeralKey)

        ({ SenderIdentityKey = ourEndpoint.IdentityKey.ExportSubjectPublicKeyInfoPem().ToCharArray()
           SenderEphemeralKey = ourEndpoint.EphemeralKey.ExportSubjectPublicKeyInfoPem().ToCharArray()
           OTPKHash = theirPrekeyHash },
         receiverRatchet)

    let handleInitMessage (endpoint: Endpoint) initializationMessage =
        
        let senderIdentityKey = ECDiffieHellman.Create()
        senderIdentityKey.ImportFromPem(ReadOnlySpan(initializationMessage.SenderIdentityKey))

        let senderEphemeralPubKey = ECDiffieHellman.Create()
        senderEphemeralPubKey.ImportFromPem(ReadOnlySpan(initializationMessage.SenderEphemeralKey))

        if endpoint.OneTimePrekeys.ContainsKey(initializationMessage.OTPKHash) then
            let otpk = endpoint.OneTimePrekeys[initializationMessage.OTPKHash]
            let sk =
                X3DH.ReceiverKey
                    endpoint.IdentityKey
                    otpk
                    senderIdentityKey.PublicKey
                    senderEphemeralPubKey.PublicKey

            let receiverRatchet =
                DoubleRatchet.ratchetInit sk endpoint.EphemeralKey (Some senderEphemeralPubKey.PublicKey)

            let endpointWithoutOTPK =
                { endpoint with
                    OneTimePrekeys =
                        endpoint.OneTimePrekeys
                        |> Map.filter (fun k _ -> k <> initializationMessage.OTPKHash) }

            Ok(endpointWithoutOTPK, receiverRatchet)
        else
            Error "Given one-time-prekey was not found on the endpoint"
