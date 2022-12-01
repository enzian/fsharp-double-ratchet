open BenchmarkDotNet.Running
open HeaderTests
open BenchmarkDotNet.Configs
open BenchmarkDotNet.Validators
open BenchmarkDotNet.Loggers
open BenchmarkDotNet.Columns

[<EntryPoint>]
let main argv =
    let config =
        (new ManualConfig())
            .WithOptions(ConfigOptions.DisableOptimizationsValidator)
            .AddValidator(JitOptimizationsValidator.DontFailOnError)
            .AddLogger(ConsoleLogger.Default)
            .AddColumnProvider(DefaultColumnProviders.Instance)

    let result = BenchmarkRunner.Run<DecodeBenchmarks>(config)
    0
