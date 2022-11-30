module Tests

open Xunit
open Signal.DoubleRatchet.DoubleRatchet
open System.Security.Cryptography
open FsUnit.Xunit

[<Fact>]
let ``When transmitting a message from Alice to Bob, Bob should decrypt the message correctly`` () =
    let psk = [|0uy..31uy|]
    let bob = ratchetInit psk (ECDiffieHellman.Create()) None
    let alice = ratchetInit psk (ECDiffieHellman.Create()) (Some bob.DHs.PublicKey)

    let (alice, msg, header) = EncryptMessage alice [|1uy..3uy|]

    let (bob, output) = DecryptMessage bob header msg

    output |> should equal [|1uy..3uy|]
