using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Utilities;

namespace Tcs;

internal static class Pairing
{
    internal static string Fingerprint(byte[] blob) => "SHA256:" + Convert.ToBase64String(TcsCrypto.Fingerprint(blob)).TrimEnd('=');

    internal static string PublicLine(byte[] blob)
    {
        var key = OpenSshPublicKeyUtilities.ParsePublicKey(blob);
        if (key is not (Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters or Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters or Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters))
            throw new InvalidDataException("不支持的配对公钥类型。");
        var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(blob);
        return Encoding.ASCII.GetString(blob, 4, length) + " " + Convert.ToBase64String(blob);
    }

    internal static void Confirm(string fingerprint, string? expected)
    {
        if (expected is not null)
        {
            if (!string.Equals(expected, fingerprint, StringComparison.Ordinal))
                throw new InvalidOperationException($"指纹不匹配。实际：{fingerprint}；提供：{expected}");
            return;
        }
        if (Console.IsInputRedirected)
            throw new InvalidOperationException($"需要交互式核对指纹 {fingerprint}。请在终端运行，或用 --trust-fingerprint 指定通过可信渠道核对的完整指纹。");
        Console.Error.Write("请通过可信渠道核对以上指纹。确认信任请输入 yes，其他输入取消：");
        if (Console.ReadLine() != "yes") throw new InvalidOperationException("已取消，未授权或保存新身份。");
    }

#if TCS_TESTING
    internal static void Export(string identity, string output)
#else
    internal static void Export(string output)
#endif
    {
#if !TCS_TESTING
        var identity = Deployment.ClientKey;
#endif
        Deployment.ValidatePair(identity);
        var blob = TcsCrypto.PublicBlob(TcsCrypto.ReadPrivateKey(identity));
        var line = PublicLine(blob);
        var fingerprint = Fingerprint(blob);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new() { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("type", "tcs-pairing");
            writer.WriteNumber("version", 1);
            writer.WriteString("publicKey", line);
            writer.WriteString("fingerprint", fingerprint);
            writer.WriteEndObject();
        }
        using (var file = new FileStream(Path.GetFullPath(output), FileMode.CreateNew, FileAccess.Write, FileShare.None))
            file.Write(buffer.ToArray());
        Console.WriteLine($"配对文件：{Path.GetFullPath(output)}\n主控公钥指纹：{fingerprint}\n请通过可信方式把文件交给被控端，并核对导入时显示的指纹。文件不含私钥。");
    }

#if TCS_TESTING
    internal static Task ImportAsync(string input, string authorizedKeys, string hostKey, string? expected)
#else
    internal static Task ImportAsync(string input, string? expected)
#endif
    {
#if !TCS_TESTING
        var authorizedKeys = Deployment.AuthorizedKeys;
        var hostKey = Deployment.HostKey;
#endif
        Deployment.ValidatePair(hostKey);
        byte[] blob;
        using (var file = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (file.Length > 16384) throw new InvalidDataException("配对文件超过 16 KiB 限制。");
            using var json = JsonDocument.Parse(file, new() { MaxDepth = 4 });
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("配对文件必须是 JSON 对象。");
            HashSet<string> fields = [];
            foreach (var property in root.EnumerateObject())
                if (property.Name is not ("type" or "version" or "publicKey" or "fingerprint") || !fields.Add(property.Name))
                    throw new InvalidDataException("配对文件包含未知或重复字段。");
            if (fields.Count != 4 || root.GetProperty("type").GetString() != "tcs-pairing" || root.GetProperty("version").GetInt32() != 1)
                throw new InvalidDataException("不支持的配对文件格式或版本。");
            var parts = (root.GetProperty("publicKey").GetString() ?? "").Split(' ');
            if (parts.Length != 2) throw new InvalidDataException("配对公钥格式不正确。");
            blob = Convert.FromBase64String(parts[1]);
            if (PublicLine(blob) != string.Join(' ', parts) || root.GetProperty("fingerprint").GetString() != Fingerprint(blob))
                throw new InvalidDataException("配对公钥与文件中记录的类型或指纹不一致。");
        }
        authorizedKeys = Path.GetFullPath(authorizedKeys);
        hostKey = Path.GetFullPath(hostKey);
        var fingerprint = Fingerprint(blob);
        Console.Error.WriteLine($"待授权主控公钥指纹：{fingerprint}\n授权文件：{authorizedKeys}");
        var already = File.Exists(authorizedKeys) && TcsCrypto.ReadAuthorizedKeys(authorizedKeys).Any(key => key.SequenceEqual(blob));
        if (!already || expected is not null) Confirm(fingerprint, expected);
        Directory.CreateDirectory(Path.GetDirectoryName(hostKey)!);
        using (var keyLock = new FileStream(hostKey + ".tcs-lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            Deployment.ValidatePair(hostKey);
            var hostBlob = TcsCrypto.PublicBlob(TcsCrypto.ReadPrivateKey(hostKey));
            Directory.CreateDirectory(Path.GetDirectoryName(authorizedKeys)!);
            using var authLock = new FileStream(authorizedKeys + ".tcs-lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var existing = File.Exists(authorizedKeys) ? File.ReadAllText(authorizedKeys) : "";
            if (!File.Exists(authorizedKeys) || !TcsCrypto.ReadAuthorizedKeys(authorizedKeys).Any(key => key.SequenceEqual(blob)))
                AtomicWrite(authorizedKeys, existing + (existing.Length > 0 && !existing.EndsWith('\n') ? "\n" : "") + PublicLine(blob) + "\n", true);
            Console.WriteLine($"主控端已授权。\n被控端主机指纹：{Fingerprint(hostBlob)}\n请在主控端首次连接时核对这个指纹；无需传回回执文件。\n启动被控端：tcsd\n数据固定目录：{Deployment.Data}\n如果被控端已在运行，请重启以加载授权。");
        }
        return Task.CompletedTask;
    }

    internal static void AtomicWrite(string path, string text, bool overwrite)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, text, new UTF8Encoding(false));
            if (overwrite && File.Exists(path)) File.Replace(temporary, path, null);
            else File.Move(temporary, path, false);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
