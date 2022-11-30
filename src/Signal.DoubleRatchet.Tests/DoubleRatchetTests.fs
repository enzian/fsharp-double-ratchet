module EncryptionDecryptionTests

open Xunit
open Signal.DoubleRatchet.DoubleRatchet
open System.Security.Cryptography
open FsUnit.Xunit

[<Fact>]
let ``When transmitting a message from Alice to Bob, Bob should decrypt the message correctly`` () =
    let psk = [| 0uy .. 31uy |]
    let bob = ratchetInit psk (ECDiffieHellman.Create()) None
    let alice = ratchetInit psk (ECDiffieHellman.Create()) (Some bob.DHs.PublicKey)

    let (alice, msg, header) = EncryptMessage alice [| 1uy .. 3uy |]

    let (bob, output) = DecryptMessage bob header msg

    output |> should equal [| 1uy .. 3uy |]
    msg |> should not' (equal [| 1uy .. 3uy |])

[<Fact>]
let ``Dropped messages are skipped on the receiving side`` () =
    let psk = [| 0uy .. 31uy |]
    let bob = ratchetInit psk (ECDiffieHellman.Create()) None
    let alice = ratchetInit psk (ECDiffieHellman.Create()) (Some bob.DHs.PublicKey)

    let (alice, _, _) = EncryptMessage alice [| 1uy .. 3uy |] // this message is 'lost'
    let (_, msg, header) = EncryptMessage alice [| 1uy .. 3uy |] // this message will be decrypted

    let (_, output) = DecryptMessage bob header msg // Bob will decrypt the second message which should add a new entry to the skipped messages map in the state

    output |> should equal [| 1uy .. 3uy |]