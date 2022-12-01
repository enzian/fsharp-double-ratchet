module HeaderTests

open Xunit
open FsUnit.Xunit
open Signal.DoubleRatchet.Header

[<Fact>]
let ``Headers can be encoded and decoded`` () =
    let subject = { DHs = [|0uy..32uy|]; PN = 1120u; Ns = 2033u }

    subject |> Encode |> Decode |> should equal subject