# fsharp-double-ratchet

This project aims to implement the [double-ratchet protocol](https://signal.org/docs/specifications/doubleratchet/) used most notably by the Signal Messaenger in order to transmit end-to-end encrypted messages. This library should enable developers to implement the same kinds of secure messaging infrastructure that powers all best-in-class E2E encrypted messaging apps.

## Discalimer and Compatibility

This repo contains a combination of libraries that can be used to implement end-to-end encrypted messaging in an application. They are not built to be compatible with the Whisper Systems Signal messaging systems and offer so such guarantee.

## Usage

### Tripple DH Key Aggreement

Before two parties can exchange messages using the Double Ratchet protocol, they need to agree on a root/session key. This can be done using the X3DH key aggreement protocol. This protocol allows members to establish a shared secret through an asynchronous exchange of messages and offers cryptogaphic deniability and forward secrecy.

```fsharp
// Alice's identity and ephemeral keypair
let IKa = ECDiffieHellman.Create();
let EKa = ECDiffieHellman.Create();

// Bobs identity and prekey pair
let IKb = ECDiffieHellman.Create();
let PKb = ECDiffieHellman.Create();
let PKbSig = signPrekey IKb PKb.PublicKey.ExportSubjectPublicKeyInfo()

// Alice uses this key to initialize the Double Ratchet protocol
let SKa = SenderKey IKa EKa IKb.PublicKey PKb.PublicKey PKbSig 

// Bob uses this key to initialize the Double Ratchet protocol
let SKb = ReceiverKey IKb PKb IKa.PublicKey EKa.PublicKey

SKa = Skb |> should be True
```

### Double Ratchet
In order to use exchange messages using the Double Ratchet protocol, both parties need two things:

* a ECDH Keypair
* a shared secret key (can be acquired using X3DH or similar other key agreement protocols)

```fsharp
// Create the ECDH Keypairs for alice and bob
let alice = ECDiffieHellman.Create()
let bob   = ECDiffieHellman.Create()

// initialize the ratchet states for both parties and we assume Alice to be sending a message to Bob for the first time
let state_bob   = ratchetInit psk bob None
let state_alice = ratchetInit psk alice (Some bob_state.DHs.PublicKey)

// Alice can now encrypt the first message to Bob. This will alter Alice's ratchet which must be stored to enable further communication. We can just shadow the same variable again since we do not need to store the previous state in order to encrypt or decrypt future messages.
let (alice, msg_cyphertext, msg_header) = EncryptMessage alice [|1uy..3uy|]

// Bob will now decrypt the message. As with Alice's ratched before, this will alter Bob's ratchet, which must be stored for future communication as well.
let (bob, cleartext) = DecryptMessage bob msg_header msg_cyphertext

// the decrypted content must match the content sent by Alice
Assert.Equals [|1uy..3uy|] cleartext
```

If Bob would now like to respond to Alice, all he has to do is encrypting a message using his new ratchet:
```fsharp
let (bob, msg_cyphertext, msg_header) = EncryptMessage new_state_bob [|5uy..8uy|]
let (alice, cleartext) = DecryptMessage alice msg_header msg_cyphertext
Assert.Equals [|5uy..8uy|] cleartext
```

## Features

What features are already implemented or planned?:

- [x] Message Encryption and Decrytion
- [x] Message Skipping
- [x] Out-Of-Order Messages
- [x] HMAC digests to authenticate decrypted content
- [x] X3DH for initial key exchange
- [x] OPKs for X3DH key exchange
- [ ] Message Header Encryption
- [ ] (X)Ed25519 Signature Algorithms that enable X3DH
