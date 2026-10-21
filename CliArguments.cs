using System.Text;

namespace Tcs;

internal static class CliArguments
{
    internal static Dictionary<string, string> Parse(string[] args)
    {
        Dictionary<string, string> options = new(StringComparer.Ordinal);
        var flags = args.Where(argument => argument is "--json" or "--meta" or "--verbose").Distinct().ToArray();
        args = args.Where(argument => argument is not ("--json" or "--meta" or "--verbose")).ToArray();
        var i = args.FirstOrDefault() == "--tcs-client" ? 1 : 0;
        var positional = i < args.Length && !args[i].StartsWith('-');
        if (positional)
        {
            options.Add("--host", args[i++]);
            var operation = i < args.Length && !args[i].StartsWith('-') ? args[i++] : "health";
            options.Add("--operation", operation);
            if (operation is "exec" or "upload" && i < args.Length && !args[i].StartsWith('-'))
                options.Add(operation == "exec" ? "--script" : "--file", args[i++]);
        }
        for (; i < args.Length; i += 2)
        {
            var name = args[i];
            if (name is not ("--host" or "--port" or "--trust-fingerprint" or "--operation" or "--script" or "--script-base64" or "--file" or "--max-output"))
                throw new ArgumentException($"Unknown option or extra positional argument: {name}. Run tcs --help.");
            if (i + 1 >= args.Length || args[i + 1].StartsWith("--") || !options.TryAdd(name, args[i + 1]))
                throw new ArgumentException($"Duplicate option or missing value: {name}");
        }
        var op = options.GetValueOrDefault("--operation", "health");
        if (op is not ("health" or "exec" or "upload"))
            throw new ArgumentException($"Unknown operation: {op}. Available: health, exec, upload.");
        if (string.IsNullOrWhiteSpace(options.GetValueOrDefault("--host", "127.0.0.1")))
            throw new ArgumentException("The host address cannot be empty.");
        if (!int.TryParse(options.GetValueOrDefault("--port", "10122"), out var port) || port is < 1 or > 65535)
            throw new ArgumentException("--port must be an integer from 1 to 65535.");
        if (options.TryGetValue("--max-output", out var maxOutput))
        {
            if (!int.TryParse(maxOutput, out var cap) || cap < 0)
                throw new ArgumentException("--max-output must be an integer >= 0 (characters; 0 = unlimited).");
            if (op != "exec") throw new ArgumentException("--max-output only applies to exec.");
        }
        if (op != "exec" && flags.Contains("--meta")) throw new ArgumentException("--meta only applies to exec.");
        foreach (var flag in flags) options[flag] = "true";
        var sources = new[] { "--script", "--script-base64", "--file" }.Count(options.ContainsKey);
        if (op == "health" && sources != 0)
            throw new ArgumentException("health does not accept script or file arguments.");
        if (op == "exec" && (sources > 1 || positional && sources == 0))
            throw new ArgumentException("exec needs exactly one source: Python source, --file <local UTF-8 file> or --script-base64 <content>; they cannot be combined.");
        if (op == "upload" && (!options.ContainsKey("--file") || sources != 1))
            throw new ArgumentException("upload needs one local file: tcs <host> upload <file>.");
        if (options.TryGetValue("--file", out var file) && string.IsNullOrWhiteSpace(file))
            throw new ArgumentException("The file path cannot be empty.");
        return options;
    }

    internal static async Task<string> ReadScriptAsync(Dictionary<string, string> options)
    {
        if (options.TryGetValue("--file", out var path))
        {
            var bytes = await File.ReadAllBytesAsync(path);
            var start = bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }) ? 3 : 0;
            return new UTF8Encoding(false, true).GetString(bytes, start, bytes.Length - start);
        }
        if (options.TryGetValue("--script-base64", out var encoded))
            return new UTF8Encoding(false, true).GetString(Convert.FromBase64String(encoded));
        return options.GetValueOrDefault("--script", "print('ok')");
    }
}
