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
                throw new ArgumentException($"未知参数或多余的位置参数：{name}。请运行 tcs --help。");
            if (i + 1 >= args.Length || args[i + 1].StartsWith("--") || !options.TryAdd(name, args[i + 1]))
                throw new ArgumentException($"参数重复或缺少值：{name}");
        }
        var op = options.GetValueOrDefault("--operation", "health");
        if (op is not ("health" or "exec" or "upload"))
            throw new ArgumentException($"未知操作：{op}。可用操作：health、exec、upload。");
        if (string.IsNullOrWhiteSpace(options.GetValueOrDefault("--host", "127.0.0.1")))
            throw new ArgumentException("被控端地址不能为空。");
        if (!int.TryParse(options.GetValueOrDefault("--port", "10122"), out var port) || port is < 1 or > 65535)
            throw new ArgumentException("--port 必须是 1 到 65535 之间的整数。");
        if (options.TryGetValue("--max-output", out var maxOutput))
        {
            if (!int.TryParse(maxOutput, out var cap) || cap < 0)
                throw new ArgumentException("--max-output 必须是不小于 0 的整数（字符数，0 表示不限制）。");
            if (op != "exec") throw new ArgumentException("--max-output 仅适用于 exec。");
        }
        if (op != "exec" && flags.Contains("--meta")) throw new ArgumentException("--meta 仅适用于 exec。");
        foreach (var flag in flags) options[flag] = "true";
        var sources = new[] { "--script", "--script-base64", "--file" }.Count(options.ContainsKey);
        if (op == "health" && sources != 0)
            throw new ArgumentException("health 不接受脚本或文件参数。");
        if (op == "exec" && (sources > 1 || positional && sources == 0))
            throw new ArgumentException("exec 须选择一种源码输入：Python 源码、--file <本地 UTF-8 文件> 或 --script-base64 <内容>，不能混用。");
        if (op == "upload" && (!options.ContainsKey("--file") || sources != 1))
            throw new ArgumentException("upload 须指定一个本地文件：tcs <host> upload <file>。");
        if (options.TryGetValue("--file", out var file) && string.IsNullOrWhiteSpace(file))
            throw new ArgumentException("文件路径不能为空。");
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
