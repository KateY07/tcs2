using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Tcs;

internal static class HostTrust
{
    internal static async Task<string> ResolveAsync(string host, int port, string identity, string directory, string? legacyKey, string? expected)
    {
        var normalized = IPAddress.TryParse(host, out var address) ? address.ToString() : host.ToLowerInvariant().TrimEnd('.');
        var name = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{normalized}:{port}"))).ToLowerInvariant() + ".pub";
        var path = Path.Combine(Path.GetFullPath(directory), name);
        var existing = File.Exists(path) ? path : legacyKey is not null && File.Exists(legacyKey) ? legacyKey : null;
        if (existing is not null)
        {
            if (expected is not null && Pairing.Fingerprint(TcsCrypto.ReadPublicKeyBlob(existing)) != expected)
                throw new CryptographicException("提供的指纹与已固定公钥不一致；不会覆盖原身份。");
            return existing;
        }
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var blob = await global::tcs.InspectServerKeyAsync(host, port, identity, deadline.Token);
        var fingerprint = Pairing.Fingerprint(blob);
        Console.Error.WriteLine($"首次连接被控端 [{host}]:{port}\n被控端主机指纹：{fingerprint}");
        Pairing.Confirm(fingerprint, expected);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        try { Pairing.AtomicWrite(path, Pairing.PublicLine(blob) + "\n", false); }
        catch (IOException) when (File.Exists(path))
        {
            if (!TcsCrypto.ReadPublicKeyBlob(path).SequenceEqual(blob))
                throw new CryptographicException("另一个进程已保存不同的主机公钥；拒绝覆盖。");
            Console.Error.WriteLine("其他连接已保存相同的主机公钥。");
        }
        Console.Error.WriteLine($"已固定被控端公钥：{path}\n正在使用已确认的身份重新连接……");
        return path;
    }
}
