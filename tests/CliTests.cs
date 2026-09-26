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
        Check(count == 34);
        Console.WriteLine($"PASS CLI: {count} assertions");
    }
}
