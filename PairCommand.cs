using System.Text;
using System.Text.Json;

namespace Tcs;

// "tcs pair <host> <code>" on the controller and "tcsd audit" on the controlled PC.
internal static class PairCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length < 2 || args[0].StartsWith('-') || args[1].StartsWith('-'))
            throw new ArgumentException("Usage: tcs pair <host> <code> [--port N] [--json]");
        var host = args[0];
        var code = args[1];
        var port = 10122;
        var json = false;
        for (var i = 2; i < args.Length; i++)
        {
            if (args[i] == "--json") json = true;
            else if (args[i] == "--port" && i + 1 < args.Length && int.TryParse(args[++i], out port) && port is >= 1 and <= 65535) { }
            else throw new ArgumentException($"Unknown or invalid pair option: {args[i]}");
        }
        Spake2.NormalizeCode(code);   // reject a malformed code before touching the network
        Deployment.RequireKey(Deployment.ClientKey);
        var clientBlob = TcsCrypto.PublicBlob(TcsCrypto.ReadPrivateKey(Deployment.ClientKey));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            var (hostBlob, already) = await PairClient.PairAsync(host, port, code, clientBlob, deadline.Token);
#if TCS_TESTING
            HostTrust.PinPaired(host, port, Deployment.KnownHosts, hostBlob);   // the harness has its own entry points; this keeps the file compiling
#else
            HostTrust.PinPaired(host, port, hostBlob);
#endif
            var hostFingerprint = Pairing.Fingerprint(hostBlob);
            var controllerFingerprint = Pairing.Fingerprint(clientBlob);
            if (json)
                Console.WriteLine(Json(("result", already ? "ALREADY_PAIRED" : "PAIRED"), ("host", host), ("port", port), ("hostFingerprint", hostFingerprint), ("controllerFingerprint", controllerFingerprint)));
            else
                Console.WriteLine($"{(already ? "Already paired with" : "Paired with")} {host}:{port}\nHost fingerprint: {hostFingerprint}\nThis controller ({controllerFingerprint}) is authorized there. Try: tcs {host} health");
            return 0;
        }
        catch (PairException refused)
        {
            var left = refused.AttemptsLeft >= 0 ? $" ({refused.AttemptsLeft} attempts left)" : "";
            var retry = refused.RetryAfterSeconds > 0 ? $" Retry in {refused.RetryAfterSeconds} s." : "";
            if (json)
                Console.WriteLine(Json(("result", PairException.Name(refused.Result)), ("message", refused.Message), ("attemptsLeft", refused.AttemptsLeft), ("retryAfterSeconds", refused.RetryAfterSeconds)));
            Console.Error.WriteLine($"tcs: pair failed: {PairException.Name(refused.Result)}: {refused.Message}{left}{retry}");
            return PairException.ExitCode(refused.Result);
        }
    }

    static string Json(params (string Name, object Value)[] fields)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var (name, value) in fields)
            {
                if (value is int number) writer.WriteNumber(name, number);
                else writer.WriteString(name, value.ToString());
            }
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    // tcsd audit [--tail N]: the last N events of data\tcs-audit.log, one compact line each.
    public static void ShowAudit(string[] args)
    {
        var tail = 20;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--tail" && i + 1 < args.Length && int.TryParse(args[++i], out tail) && tail > 0) continue;
            throw new ArgumentException("Usage: tcsd audit [--tail N]");
        }
        var path = Path.Combine(Deployment.Data, "tcs-audit.log");
        if (!File.Exists(path))
        {
            Console.WriteLine($"No audit log yet: {path}");
            return;
        }
        foreach (var line in File.ReadLines(path).TakeLast(tail))
        {
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                string Text(string name) => root.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : "-";
                var evt = root.TryGetProperty("event", out _) ? Text("event") : Text("endpoint").TrimStart('/').Replace("v1/", "");
                var result = root.TryGetProperty("result", out _) ? Text("result") : root.TryGetProperty("exitCode", out _) ? "exit=" + Text("exitCode") + (Text("timedOut") == "True" ? " timeout" : "") : "-";
                var detail = root.TryGetProperty("detail", out _) ? Text("detail") : root.TryGetProperty("scriptSha256", out _) ? "sha256=" + Text("scriptSha256")[..Math.Min(12, Text("scriptSha256").Length)] : Text("files");
                Console.WriteLine($"{Text("timestamp")}  {evt,-18} {Text("source"),-15} {Text("clientFingerprint"),-52} {result}  {detail}");
            }
            catch (JsonException) { Console.WriteLine(line); }
        }
    }
}
