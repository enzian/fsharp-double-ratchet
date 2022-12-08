module X3DHTests

open Xunit
open Signal.Protocol.X3DH
open System.Security.Cryptography
open FsUnit.Xunit

[<Fact>]
let ``Bob should reject Alice's prekey signature if it's invalid`` () =
    // IdentityKeys
    let IKa = ECDiffieHellman.Create();
    let IKb = ECDiffieHellman.Create();
    
    // ephemeral keys
    let EKa = ECDiffieHellman.Create();

    // pre keys
    let PKa = ECDiffieHellman.Create();
    let PKb = ECDiffieHellman.Create();

    (fun () -> SenderKey IKa EKa IKb.PublicKey PKb.PublicKey [|0uy..10uy|] |> ignore) |> should throw typeof<SignaturValidationError>

[<Fact>]
let ``Bob should calculate the shared key`` () =
    // IdentityKeys
    let IKa = ECDiffieHellman.Create();
    let IKb = ECDiffieHellman.Create();
    
    // ephemeral keys
    let EKa = ECDiffieHellman.Create();

    // pre keys
    // let PKa = ECDiffieHellman.Create();
    let PKb = ECDiffieHellman.Create();

    // signatures
    let ecDsa = ECDsa.Create(IKb.ExportParameters(true));
    let PKbSig = ecDsa.SignData(PKb.PublicKey.ExportSubjectPublicKeyInfo(), HashAlgorithmName.SHA512);

    SenderKey IKa EKa IKb.PublicKey PKb.PublicKey PKbSig |> should not' (equal [||])

[<Fact>]
let ``Bob and Alice should derive a matching key`` () =
    // IdentityKeys
    let IKa = ECDiffieHellman.Create();
    let IKb = ECDiffieHellman.Create();
    
    // ephemeral keys
    let EKa = ECDiffieHellman.Create();

    // pre keys
    let PKb = ECDiffieHellman.Create();

    // signatures
    let ecDsab = ECDsa.Create(IKb.ExportParameters(true));
    let PKbSig = ecDsab.SignData(PKb.PublicKey.ExportSubjectPublicKeyInfo(), HashAlgorithmName.SHA512);

    let SKa = SenderKey IKa EKa IKb.PublicKey PKb.PublicKey PKbSig
    let SKb = ReceiverKey IKb PKb IKa.PublicKey EKa.PublicKey

    SKa |> should equal SKb