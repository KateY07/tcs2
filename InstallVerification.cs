using System.Security.Cryptography;

namespace Tcs;

internal static class InstallVerification
{
    internal static async Task RunAsync(int port, string clientKey, string serverKey, string data)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        foreach (var address in new[] { "127.0.0.1", "::1" })
        {
            var client = new global::tcs(address, port, clientKey, serverKey);
            var health = await client.HealthAsync(timeout.Token);
            if (health.GetProperty("status").GetString() != "ok") throw new IOException("Health check failed");
            Console.WriteLine($"PASS authenticated health: {address}:{port}");
        }
        var test = new global::tcs("::1", port, clientKey, serverKey);
        var result = await test.ExecAsync("import platform; print('TCS_INSTALL_CHECK:' + platform.python_version())", 30, timeout.Token);
        if (result.GetProperty("TimedOut").GetBoolean() || result.GetProperty("ExitCode").GetInt32() != 0 ||
            !result.GetProperty("Stdout").GetString()!.StartsWith("TCS_INSTALL_CHECK:", StringComparison.Ordinal))
            throw new IOException("Python check failed: " + result.GetRawText());
        Console.WriteLine("PASS remote Python: " + result.GetProperty("Stdout").GetString()!.Trim());
        var bytes = RandomNumberGenerator.GetBytes(32768);
        var uploaded = await test.UploadAsync("installer-check.bin", bytes, timeout.Token);
        var stored = uploaded.GetProperty("saved")[0].GetString()!;
        if (Path.GetFileName(stored) != stored) throw new IOException("Invalid upload response filename");
        var destination = Path.Combine(data, "uploads", stored);
        try
        {
            if (!(await File.ReadAllBytesAsync(destination, timeout.Token)).SequenceEqual(bytes))
                throw new IOException("Upload content mismatch");
            Console.WriteLine("PASS encrypted upload: 32768 bytes identical");
        }
        finally { File.Delete(destination); }
    }
}
