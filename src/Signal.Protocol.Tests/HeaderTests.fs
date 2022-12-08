module HeaderTests

open Xunit
open FsUnit.Xunit
open Signal.Protocol.Header

[<Fact>]
let ``Headers can be encoded and decoded`` () =
    let subject =
        { DHs = [| 0uy .. 32uy |]
          PN = 1120u
          Ns = 2033u }

    subject |> Encode |> Decode |> should equal subject

open BenchmarkDotNet.Attributes
open BenchmarkDotNet.Jobs
open System


exception DecodeError of string

// This in an alternate implementation of the Decode functionality in Signal.DoubleRatchet.Header which performs much slower. Run the Benchmark to see how much slower
let DecodeMatchAndSlice (coded: byte array) =
    let DHs, PN, Ns =
        match (coded |> Array.toList) with
        | b0 :: b1 :: b2 :: b3 :: tail ->
            let DHs_length = BitConverter.ToInt32(System.ReadOnlySpan([| b0; b1; b2; b3 |]))
            let DHs = tail[.. (DHs_length - 1)] |> List.toArray

            let PN, Ns =
                match tail[DHs_length..] with
                | b0 :: b1 :: b2 :: b3 :: tail ->
                    let PN = BitConverter.ToUInt32(System.ReadOnlySpan([| b0; b1; b2; b3 |]))

                    let Ns =
                        match tail with
                        | b0 :: b1 :: b2 :: b3 :: _ -> BitConverter.ToUInt32(System.ReadOnlySpan([| b0; b1; b2; b3 |]))
                        | _ -> raise (DecodeError "not enough bytes to decode Ns")

                    PN, Ns
                | _ -> raise (DecodeError "not enough bytes to decode PN")

            DHs, PN, Ns
        | _ -> raise (DecodeError "not enough bytes to decode DHs header")

    { DHs = DHs; PN = PN; Ns = Ns }

[<SimpleJob(RuntimeMoniker.Net70)>]
type DecodeBenchmarks() =
    [<Params(100, 1000, 10000, 100000, 1000000)>]
    member val size = 0 with get, set

    member val coded = [| 1uy; 0uy; 0uy; 0uy; 1uy; 2uy; 0uy; 0uy; 0uy; 4uy; 0uy; 0uy; 0uy |] with get, set

    [<Benchmark(Baseline = true)>]
    member this.MatchAndCons() =
        [| 0 .. this.size |] |> Array.map (fun (_) -> this.coded |> Decode)

    [<Benchmark>]
    member this.ArraySlicing() =
        [| 0 .. this.size |] |> Array.map (fun (_) -> this.coded |> DecodeMatchAndSlice)
