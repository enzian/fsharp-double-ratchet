module Tests

open Xunit
open Signal.DoubleRatchet.DoubleRatchet
open System.Security.Cryptography
open FsUnit.Xunit

[<Fact>]
let ``When transmitting a message from Alice to Bob, Bob should receive a`` () =
    let psk = [|0uy..31uy|]
    let bob = ratchetInit psk (ECDiffieHellman.Create()) None
    let alice = ratchetInit psk (ECDiffieHellman.Create()) (Some bob.DHs.PublicKey)

    let (_, msg, header) = EncryptMessage alice [|1uy..3uy|] [||]

    let (_, output) = DecryptMessage bob header msg

    output |> should equal [|1uy..3uy|]
