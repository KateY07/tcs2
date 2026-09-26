using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Tcs;

internal static class HostTrust
{
#if !TCS_TESTING
    internal static string PinnedPath(string host, int port)
    {
        var endpoint = EndpointPath(host, port, Deployment.KnownHosts);
        if (File.Exists(endpoint)) return endpoint;
        if (File.Exists(Deployment.HostKey + ".pub")) return Deployment.HostKey + ".pub";
        throw new InvalidOperationException("尚未固定此被控端身份，请先通过 tcs --host 连接并核对指纹。");
    }
#endif

    static string EndpointPath(string host, int port, string directory)
    {
        var normalized = IPAddress.TryParse(host, out var address) ? address.ToString() : host.ToLowerInvariant().TrimEnd('.');
        var name = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{normalized}:{port}"))).ToLowerInvariant() + ".pub";
        return Path.Combine(Path.GetFullPath(directory), name);
    }

#if TCS_TESTING
    internal static async Task<string> ResolveAsync(string host, int port, string identity, string directory, string? legacyKey, string? expected)
#else
    internal static async Task<string> ResolveAsync(string host, int port, string? expected)
#endif
    {
#if !TCS_TESTING
        var directory = Deployment.KnownHosts;
        var legacyKey = Deployment.HostKey + ".pub";
#endif
        var path = EndpointPath(host, port, directory);
        var existing = File.Exists(path) ? path : legacyKey is not null && File.Exists(legacyKey) ? legacyKey : null;
        if (existing is not null)
        {
            var savedFingerprint = Pairing.Fingerprint(TcsCrypto.ReadPublicKeyBlob(existing));
            if (existing != path)
                Console.Error.WriteLine($"旧固定公钥正在生效：{existing}\n固定指纹：{savedFingerprint}\n目标 [{host}]:{port} 没有独立记录，使用旧固定公钥严格校验，因此不会询问首次确认。若目标不匹配将拒绝连接，请勿盲目删除或覆盖此文件。");
            else Console.Error.WriteLine($"正在校验已保存的被控端身份：[{host}]:{port}\n信任记录：{existing}");
            if (expected is not null && Pairing.Fingerprint(TcsCrypto.ReadPublicKeyBlob(existing)) != expected)
                throw new CryptographicException("提供的指纹与已固定公钥不一致；不会覆盖原身份。");
            return existing;
        }
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Console.Error.WriteLine($"正在探测 [{host}]:{port} 的主机身份；核对完成前不发送指令或文件。");
#if TCS_TESTING
        var blob = await global::tcs.InspectServerKeyAsync(host, port, identity, deadline.Token);
#else
        var blob = await global::tcs.InspectServerKeyAsync(host, port, deadline.Token);
#endif
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
