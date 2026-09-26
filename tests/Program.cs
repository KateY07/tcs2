// Test-only adapter: explicit fixture paths never enter the published CLI.
using System.Net;
using Tcs;

try
{
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
        await new tcsd(Option("--authorized-keys"), Option("--host-key"), Option("--data")).RunAsync(IPAddress.Any, int.Parse(Option("--port", "10122")));
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
    Console.Error.WriteLine(Deployment.FailureHint(error));
    Console.Error.WriteLine($"tcs: operation failed: {error}");
    Environment.ExitCode = 1;
}
