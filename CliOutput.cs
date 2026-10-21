using System.Text.Json;

namespace Tcs;

// Default CLI output contract (shared by the shipped tcs and the test fixture):
//   exec    stdout = remote stdout, stderr = remote stderr (+ one "tcs: ..." line only when something is abnormal
//           or --meta is given), exit code = remote exit code.
//   health / upload / --json   raw JSON on stdout (unchanged), exit code 0.
// tcs's own failures (connection, identity, arguments) exit 255 so they never collide with a remote script's code.
internal static class CliOutput
{
    internal const int Failure = 255;
    internal const int Timeout = 124;
    internal const int UnmappableRemoteExit = 254;

    internal const string ClientUsage = "usage: tcs <host> [health | exec <py source> | exec --file <f.py> | upload <file>] [--port N] [--max-output N] [--json] [--meta]\n       tcs pair <host> <code> [--port N]\ndetails: tcs --help";
    internal const string DaemonUsage = "usage: tcsd [--port N] [--python <path>] | tcsd pair | tcsd pairing import <file.tcs-pair> | tcsd audit [--tail N]\ndetails: tcsd --help";

    internal static int Render(string operation, JsonElement result, IReadOnlyDictionary<string, string> options, TextWriter stdout, TextWriter stderr, TimeSpan total)
    {
        if (operation != "exec" || options.ContainsKey("--json"))
        {
            stdout.WriteLine(result.GetRawText());
            return 0;
        }
        var text = Text(result, "Stdout");
        var errorText = Text(result, "Stderr");
        int? exitCode = result.TryGetProperty("ExitCode", out var code) && code.ValueKind == JsonValueKind.Number ? code.GetInt32() : null;
        var timedOut = result.TryGetProperty("TimedOut", out var timeout) && timeout.ValueKind == JsonValueKind.True;
        stdout.Write(text);
        stderr.Write(errorText);

        var notes = new List<string>();
        if (timedOut) notes.Add("timeout");
        else if (exitCode is not 0 || options.ContainsKey("--meta")) notes.Add($"exit={exitCode}");
        if (Number(result, "StdoutOmitted") is > 0 and var outOmitted) notes.Add($"stdout-omitted={outOmitted}");
        if (Number(result, "StderrOmitted") is > 0 and var errOmitted) notes.Add($"stderr-omitted={errOmitted}");
        if (options.ContainsKey("--meta"))
            notes.Add($"task={Number(result, "DurationMs")}ms total={(long)total.TotalMilliseconds}ms out={text.Length} err={errorText.Length}");
        if (notes.Count > 0)
        {
            var last = errorText.Length > 0 ? errorText[^1] : text.Length > 0 ? text[^1] : '\n';
            if (last != '\n') stderr.WriteLine();
            stderr.WriteLine("tcs: " + string.Join(' ', notes));
        }
        return timedOut || exitCode is null ? Timeout : exitCode is >= 0 and <= 253 ? exitCode.Value : UnmappableRemoteExit;
    }

    internal static string FormatFailure(Exception error, bool verbose)
    {
        var hint = Deployment.FailureHint(error);
        var message = (hint is null ? "" : "tcs: " + hint + "\n") + "tcs: " + error.Message;
        return verbose ? message + "\n" + error : message;
    }

    static string Text(JsonElement result, string name) =>
        result.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";

    static long Number(JsonElement result, string name) =>
        result.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number ? value.GetInt64() : 0;
}
