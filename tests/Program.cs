// Test-only adapter: explicit fixture paths never enter the published CLI.
using System.Net;
using Tcs;

try
{
    if (args[0] == "--test-cli")
    {
        await CliTests.RunAsync();
        return;
    }
    if (args[0] == "--cli-fixture")
    {
        var parsed = CliArguments.Parse(args[3..]);
        var testClient = new tcs(parsed["--host"], int.Parse(parsed.GetValueOrDefault("--port", "10122")), args[1], args[2]);
        var started = System.Diagnostics.Stopwatch.StartNew();
        var response = parsed["--operation"] switch
        {
            "health" => await testClient.HealthAsync(),
            "exec" => await testClient.ExecAsync(await CliArguments.ReadScriptAsync(parsed), 30, default,
                parsed.TryGetValue("--max-output", out var cap) ? int.Parse(cap) : null),
            "upload" => await testClient.UploadAsync(Path.GetFileName(parsed["--file"]), await File.ReadAllBytesAsync(parsed["--file"])),
            _ => throw new ArgumentException("Unknown operation")
        };
        Environment.ExitCode = CliOutput.Render(parsed["--operation"], response, parsed, Console.Out, Console.Error, started.Elapsed);
        return;
    }
    if (args[0] == "--bench")
    {
        // --bench <client-key> <host-pub> <host> <port> <iterations> <script-file>: in-process request timings (ms).
        var benchClient = new tcs(args[3], int.Parse(args[4]), args[1], args[2]);
        var iterations = int.Parse(args[5]);
        var benchScript = await File.ReadAllTextAsync(args[6]);
        var watch = new System.Diagnostics.Stopwatch();
        var health = new List<double>();
        var exec = new List<double>();
        for (var i = 0; i < iterations; i++)
        {
            watch.Restart();
            await benchClient.HealthAsync();
            health.Add(watch.Elapsed.TotalMilliseconds);
        }
        for (var i = 0; i < iterations; i++)
        {
            watch.Restart();
            await benchClient.ExecAsync(benchScript);
            exec.Add(watch.Elapsed.TotalMilliseconds);
        }
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { health, exec }));
        return;
    }
    if (args[0] == "--pair-client")
    {
        // --pair-client <client-key> <known-hosts-dir> <host> <port> <code>: the controller side of "tcs pair" with explicit test paths.
        var clientBlob = TcsCrypto.PublicBlob(TcsCrypto.ReadPrivateKey(args[1]));
        try
        {
            var (hostBlob, already) = await PairClient.PairAsync(args[3], int.Parse(args[4]), args[5], clientBlob, CancellationToken.None);
            HostTrust.PinPaired(args[3], int.Parse(args[4]), args[2], hostBlob);
            Console.WriteLine((already ? "ALREADY_PAIRED " : "PAIRED ") + Pairing.Fingerprint(hostBlob));
            return;
        }
        catch (PairException refused)
        {
            Console.WriteLine($"{PairException.Name(refused.Result)} attemptsLeft={refused.AttemptsLeft} retryAfter={refused.RetryAfterSeconds}");
            Environment.ExitCode = PairException.ExitCode(refused.Result);
            return;
        }
    }
    if (args[0] == "--audit-production")
    {
        var assembly = System.Reflection.Assembly.LoadFrom(Path.GetFullPath(args[1]));
        var clientType = assembly.GetType("tcs", true)!;
        var serverType = assembly.GetType("tcsd", true)!;
        if (clientType.GetConstructors().Length != 1 || clientType.GetConstructors()[0].GetParameters().Length != 2 ||
            serverType.GetConstructors().Length != 1 || serverType.GetConstructors()[0].GetParameters().Length != 0)
            throw new Exception("Production constructor exposes path arguments.");
        if (clientType.GetMethod("InspectServerKeyAsync")!.GetParameters().Length != 3)
            throw new Exception("Production probe exposes identity argument.");
        if (assembly.GetType("Tcs.HostKeys") is not null || assembly.GetType("Tcs.InstallVerification") is not null)
            throw new Exception("Test key-generation/verification helpers entered production.");
        var flags = System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic;
        var pairingType = assembly.GetType("Tcs.Pairing", true)!;
        if (pairingType.GetMethod("Export", flags)!.GetParameters().Length != 1 ||
            pairingType.GetMethod("ImportAsync", flags)!.GetParameters().Length != 2)
            throw new Exception("Production pairing exposes identity arguments.");
        Console.WriteLine("PASS production assembly API: fixed identity constructors, probe and pairing; no test helpers");
        return;
    }
    string Option(string name, string fallback = "")
    {
        var index = Array.IndexOf(args, name);
        return index < 0 ? fallback : index + 1 < args.Length ? args[index + 1] : throw new ArgumentException(name);
    }
    if (args[0] == "--generate-host-key")
    {
        HostKeys.CreateOrExport(args[1]);
        return;
    }
    if (args[0] == "--validate-pair")
    {
        Deployment.ValidatePair(args[1]);
        return;
    }
    if (args[0] == "--instructions")
    {
        Console.WriteLine(Deployment.KeyInstructions(args[1] == "server"));
        return;
    }
    if (args[0] == "--verify-install")
    {
        await InstallVerification.RunAsync(int.Parse(args[1]), args[2], args[3], args[4]);
        return;
    }
    if (args.Contains("pairing"))
    {
        if (args.Contains("export")) Pairing.Export(Option("--client-key"), Option("--output"));
        else await Pairing.ImportAsync(args[3], Option("--authorized-keys"), Option("--host-key"),
            args.Contains("--trust-fingerprint") ? Option("--trust-fingerprint") : null);
        return;
    }
    if (args[0] == "--tcsd")
    {
        Environment.SetEnvironmentVariable("TCS_PYTHON_EXE", Option("--python", "python"));
        var daemon = new tcsd(Option("--authorized-keys"), Option("--host-key"), Option("--data"), int.Parse(Option("--pair-seconds", "60")));
        if (args.Contains("--pair")) { daemon.OpenPairingOnStart = true; daemon.FixedPairingCode = args.Contains("--pair-code") ? Option("--pair-code") : null; }
        await daemon.RunAsync(IPAddress.Any, int.Parse(Option("--port", "10122")));
        return;
    }
    var host = Option("--host", "127.0.0.1");
    var port = int.Parse(Option("--port", "10122"));
    var identity = Option("--client-key");
    var pin = Option("--server-key");
    if (pin.Length == 0) pin = await HostTrust.ResolveAsync(host, port, identity, Option("--known-hosts"),
        args.Contains("--legacy-key") ? Option("--legacy-key") : null,
        args.Contains("--trust-fingerprint") ? Option("--trust-fingerprint") : null);
    var client = new tcs(host, port, identity, pin);
    var operation = Option("--operation", "health");
    var result = operation switch
    {
        "health" => await client.HealthAsync(),
        "exec" => await client.ExecAsync(args.Contains("--script-base64") ? System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(Option("--script-base64"))) : Option("--script", "print('ok')")),
        "upload" => await client.UploadAsync(Path.GetFileName(Option("--file")), await File.ReadAllBytesAsync(Option("--file"))),
        _ => throw new ArgumentException(operation)
    };
    Console.WriteLine(result.GetRawText());
}
catch (Exception error)
{
    if (Deployment.FailureHint(error) is { } hint) Console.Error.WriteLine(hint);
    Console.Error.WriteLine($"tcs: operation failed: {error}");
    Environment.ExitCode = 1;
}
