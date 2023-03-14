module ProtocolTests

open Xunit
open FsUnit.Xunit
open Signal.Protocol.Messages

[<Fact>]
let ``Headers can be encoded and decoded`` () =

    subject |> Encode |> Decode |> should equal subject