namespace Signal.Protocol

module Messages =

    type SessionInitiationMsg =
        { SenderIdentityKey: char array
          SenderEphemeralKey: char array
          OTPKHash: byte array
        // Header: byte array
        // CipherMessage: byte array
         }

    type EstablishedSessionMessage =
        { Header: byte array
          CipherMessage: byte array }

    type ProtocolMessage =
        | Initialization of SessionInitiationMsg
        | EstablishedSession of EstablishedSessionMessage

module Endpoints =
    open System.Security.Cryptography
    open System.Collections.Generic
    open Messages
    open System

    type Endpoint =
        { IdentityKey: ECDiffieHellman
          EphemeralKey: ECDiffieHellman
          OneTimePrekeys: Map<byte array, ECDiffieHellman> }

    let initiateSession endpoint (initializationMessage: SessionInitiationMsg) =
        let sendIdentityKey = ECDiffieHellman.Create()
        sendIdentityKey.ImportFromPem(ReadOnlySpan(initializationMessage.SenderIdentityKey))

        let senderEphemeralPubKey = ECDiffieHellman.Create()
        sendIdentityKey.ImportFromPem(ReadOnlySpan(initializationMessage.SenderEphemeralKey))

        if endpoint.OneTimePrekeys.ContainsKey(initializationMessage.OTPKHash) then
            let otpk = endpoint.OneTimePrekeys[initializationMessage.OTPKHash]

            let sk =
                X3DH.ReceiverKey
                    endpoint.IdentityKey
                    endpoint.EphemeralKey
                    sendIdentityKey.PublicKey
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
            Error "Given one-time-prekey was not found on the given endpoint"
// else Error "failed to find a corresponding one-time prekey"
