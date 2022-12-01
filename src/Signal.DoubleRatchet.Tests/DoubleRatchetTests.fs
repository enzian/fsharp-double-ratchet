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

[<Fact>]
let ``Messages can be decrypted out of order`` () =
    let psk = [| 0uy .. 31uy |]
    let bob = ratchetInit psk (ECDiffieHellman.Create()) None
    let alice = ratchetInit psk (ECDiffieHellman.Create()) (Some bob.DHs.PublicKey)

    let (alice, msg1, header1) = EncryptMessage alice [| 1uy .. 3uy |] // this message is 'lost'
    let (_, msg2, header2) = EncryptMessage alice [| 4uy .. 6uy |] // this message will be decrypted

    // Bob will decrypt the second message which should add a new entry to the skipped messages map in the state
    let (_, output) = DecryptMessage bob header2 msg2 
    output |> should equal [| 4uy .. 6uy |]
    // Bob will decrypt the first message which should still work, since it's message key is taken from his states' MKSKIPPED map
    let (_, output) = DecryptMessage bob header1 msg1 
    output |> should equal [| 1uy .. 3uy |]