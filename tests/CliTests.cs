using System.Text;
using Tcs;

internal static class CliTests
{
    internal static async Task RunAsync()
    {
        var count = 0;
        void Check(bool condition)
        {
            if (!condition) throw new Exception($"CLI assertion {count + 1} failed");
            count++;
        }
        void Reject(params string[] args)
        {
            try { CliArguments.Parse(args); }
            catch (ArgumentException) { count++; return; }
            throw new Exception($"Expected rejection: {string.Join(' ', args)}");
        }
        Check(CliArguments.Parse(["alipc", "health"])["--operation"] == "health");
        Check(CliArguments.Parse(["alipc"])["--operation"] == "health");
        Check(CliArguments.Parse(["alipc", "exec", "print('hello')"])["--script"] == "print('hello')");
        Check(CliArguments.Parse(["alipc", "exec", "--file", "test file.py"])["--file"] == "test file.py");
        Check(CliArguments.Parse(["alipc", "upload", ".\\demo.txt"])["--file"] == ".\\demo.txt");
        Check(CliArguments.Parse(["fe80::1%14", "health", "--port", "3388"])["--host"] == "fe80::1%14");
        Check(CliArguments.Parse(["--host", "alipc", "--operation", "exec", "--script", "print(1)"])["--script"] == "print(1)");
        Check(CliArguments.Parse(["--tcs-client", "alipc", "health"])["--host"] == "alipc");
        Check(CliArguments.Parse(["--host", "alipc"])["--host"] == "alipc");
        Check(CliArguments.Parse(["alipc", "health", "--trust-fingerprint", "SHA256:test"])["--trust-fingerprint"] == "SHA256:test");
        Check(await CliArguments.ReadScriptAsync(CliArguments.Parse(["--operation", "exec"])) == "print('ok')");
        Check(await CliArguments.ReadScriptAsync(CliArguments.Parse(["alipc", "exec", "--script-base64", "cHJpbnQoMSk="])) == "print(1)");
        Reject("alipc", "unknown");
        Reject("alipc", "exec");
        Reject("alipc", "upload");
        Reject("alipc", "exec", "--file");
        Reject("alipc", "exec", "--file", "");
        Reject("alipc", "exec", "print(1)", "--file", "test.py");
        Reject("alipc", "exec", "--script", "print(1)", "--script-base64", "eA==");
        Reject("alipc", "upload", "a.txt", "b.txt");
        Reject("alipc", "upload", "a.txt", "--file", "b.txt");
        Reject("alipc", "health", "--file", "test.py");
        Reject("alipc", "health", "--host", "other");
        Reject("alipc", "health", "--operation", "exec");
        Reject("alipc", "health", "--port", "0");
        Reject("alipc", "health", "--port", "65536");
        Reject("alipc", "health", "--port", "abc");
        Reject("alipc", "health", "--port", "1", "--port", "2");
        Reject("alipc", "health", "--unknown", "1");
        Reject("alipc", "upload", "--file", "a.txt", "--script", "print(1)");
        Check(CliArguments.Parse(["alipc", "exec", "print(1)", "--json", "--meta"]).ContainsKey("--json"));
        Check(CliArguments.Parse(["alipc", "exec", "print(1)", "--max-output", "0"])["--max-output"] == "0");
        Check(CliArguments.Parse(["alipc", "health", "--verbose"]).ContainsKey("--verbose"));
        Reject("alipc", "exec", "print(1)", "--max-output", "-1");
        Reject("alipc", "exec", "print(1)", "--max-output", "abc");
        Reject("alipc", "health", "--max-output", "5");
        Reject("alipc", "health", "--meta");

        (int Code, string Out, string Err) Render(string json, params string[] flags)
        {
            var options = flags.ToDictionary(flag => flag, _ => "true");
            using var document = System.Text.Json.JsonDocument.Parse(json);
            using var stdout = new StringWriter();
            using var stderr = new StringWriter();
            var code = CliOutput.Render("exec", document.RootElement, options, stdout, stderr, TimeSpan.FromMilliseconds(250));
            return (code, stdout.ToString(), stderr.ToString().ReplaceLineEndings("\n"));
        }
        var quiet = Render("""{"ExitCode":0,"Stdout":"1\r\n","Stderr":"","TimedOut":false}""");
        Check(quiet.Code == 0 && quiet.Out == "1\r\n" && quiet.Err == "");
        var failed = Render("""{"ExitCode":3,"Stdout":"a","Stderr":"b","TimedOut":false}""");
        Check(failed.Code == 3 && failed.Out == "a" && failed.Err == "b\ntcs: exit=3\n");
        var timedOut = Render("""{"ExitCode":null,"Stdout":"","Stderr":"","TimedOut":true}""");
        Check(timedOut.Code == CliOutput.Timeout && timedOut.Err == "tcs: timeout\n");
        Check(Render("""{"ExitCode":-1073741510,"Stdout":"","Stderr":"","TimedOut":false}""").Code == CliOutput.UnmappableRemoteExit);
        Check(Render("""{"ExitCode":254,"Stdout":"","Stderr":"","TimedOut":false}""").Code == CliOutput.UnmappableRemoteExit);
        Check(Render("""{"ExitCode":253,"Stdout":"","Stderr":"","TimedOut":false}""").Code == 253);
        var truncated = Render("""{"ExitCode":0,"Stdout":"x\n","Stderr":"","TimedOut":false,"StdoutOmitted":5,"StderrOmitted":7}""");
        Check(truncated.Code == 0 && truncated.Err == "tcs: stdout-omitted=5 stderr-omitted=7\n");
        var meta = Render("""{"ExitCode":0,"Stdout":"ok\n","Stderr":"","TimedOut":false,"DurationMs":42}""", "--meta");
        Check(meta.Err == "tcs: exit=0 task=42ms total=250ms out=3 err=0\n");
        var json = Render("""{"ExitCode":3,"Stdout":"a","Stderr":"b","TimedOut":false}""", "--json");
        Check(json.Code == 0 && json.Out.ReplaceLineEndings("\n") == """{"ExitCode":3,"Stdout":"a","Stderr":"b","TimedOut":false}""" + "\n" && json.Err == "");

        // Output cap: keeps head and tail, counts what it drops, never splits a surrogate pair.
        async Task<(string Text, long Omitted)> Cap(string text, int limit) => await OutputCap.ReadAsync(new StringReader(text), limit, default);
        var small = await Cap("hello", 100);
        Check(small.Text == "hello" && small.Omitted == 0);
        var exact = await Cap(new string('a', 100), 100);
        Check(exact.Text.Length == 100 && exact.Omitted == 0);
        var big = await Cap(string.Concat(Enumerable.Range(0, 1000).Select(i => i % 10)), 100);
        Check(big.Omitted == 900 && big.Text.StartsWith("0123456789012345678901234") && big.Text.EndsWith("5678901234567890123456789") && big.Text.Contains("[tcs:"));
        Check((await Cap("abc", 0)).Text == "abc");
        var emoji = await Cap(string.Concat(Enumerable.Repeat("😀", 200)), 101);
        Check(emoji.Omitted > 0 && emoji.Text.Count(char.IsHighSurrogate) == emoji.Text.Count(char.IsLowSurrogate));
        var directory = Path.Combine(Path.GetTempPath(), "tcs-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var file = Path.Combine(directory, "中文 script.py");
        try
        {
            foreach (var bom in new[] { false, true })
            {
                await File.WriteAllTextAsync(file, "print('中文')\r\n", new UTF8Encoding(bom));
                Check(await CliArguments.ReadScriptAsync(CliArguments.Parse(["alipc", "exec", "--file", file])) == "print('中文')\r\n");
            }
            await File.WriteAllBytesAsync(file, [0xff, 0xfe, 0x00]);
            try { await CliArguments.ReadScriptAsync(CliArguments.Parse(["alipc", "exec", "--file", file])); }
            catch (DecoderFallbackException) { count++; }
            File.Delete(file);
            try
            {
                await CliArguments.ReadScriptAsync(CliArguments.Parse(["alipc", "exec", "--file", file]));
                throw new Exception("Missing file accepted");
            }
            catch (FileNotFoundException) { count++; }
        }
        finally
        {
            if (File.Exists(file)) File.Delete(file);
            Directory.Delete(directory);
        }
        Check(count == 55);
        Console.WriteLine($"PASS CLI: {count} assertions");
    }
}
