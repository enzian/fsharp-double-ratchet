namespace Signal.Protocol

open System

module Header =

    type MessageHeader = { DHs: byte[]; PN: uint; Ns: uint }

    let Encode header =
        let DHS_section =
            [ BitConverter.GetBytes(header.DHs.Length); header.DHs ] |> Array.concat

        let PN_section = BitConverter.GetBytes header.PN
        let Ns_section = BitConverter.GetBytes header.Ns
        [ DHS_section; PN_section; Ns_section ] |> Array.concat

    let Decode (coded: byte array) =
        let DHs_length = BitConverter.ToInt32(coded[0..3])
        let coded_DHs = coded[4..]
        let DHs = coded_DHs[.. (DHs_length - 1)]

        let coded_PN = coded_DHs[(DHs_length) ..]
        let PN = BitConverter.ToUInt32(coded_PN[..3])
        let coded_Ns = coded_PN[4..]
        let Ns = BitConverter.ToUInt32(coded_Ns[..3])
        { DHs = DHs; PN = PN; Ns = Ns }