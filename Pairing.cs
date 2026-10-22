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
            throw new InvalidDataException("Unsupported pairing key type.");
        var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(blob);
        return Encoding.ASCII.GetString(blob, 4, length) + " " + Convert.ToBase64String(blob);
    }

    internal static void Confirm(string fingerprint, string? expected)
    {
        if (expected is not null)
        {
            if (!string.Equals(expected, fingerprint, StringComparison.Ordinal))
                throw new InvalidOperationException($"Fingerprint mismatch. Actual: {fingerprint}; provided: {expected}");
            return;
        }
        if (Console.IsInputRedirected)
            throw new InvalidOperationException($"The fingerprint {fingerprint} must be verified interactively. Run in a terminal, or pass --trust-fingerprint with the full fingerprint verified through a trusted channel.");
        Console.Error.Write("Verify the fingerprint above through a trusted channel. Type yes to trust it, anything else cancels: ");
        if (Console.ReadLine() != "yes") throw new InvalidOperationException("Cancelled. Nothing was authorized or saved.");
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
        Console.WriteLine($"Pairing file: {Path.GetFullPath(output)}\nController key fingerprint: {fingerprint}\nDeliver the file to the controlled PC through a trusted channel and verify the fingerprint shown at import. The file contains no private key.");
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
            if (file.Length > 16384) throw new InvalidDataException("The pairing file exceeds the 16 KiB limit.");
            using var json = JsonDocument.Parse(file, new() { MaxDepth = 4 });
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("The pairing file must be a JSON object.");
            HashSet<string> fields = [];
            foreach (var property in root.EnumerateObject())
                if (property.Name is not ("type" or "version" or "publicKey" or "fingerprint") || !fields.Add(property.Name))
                    throw new InvalidDataException("The pairing file contains unknown or duplicate fields.");
            if (fields.Count != 4 || root.GetProperty("type").GetString() != "tcs-pairing" || root.GetProperty("version").GetInt32() != 1)
                throw new InvalidDataException("Unsupported pairing file format or version.");
            var parts = (root.GetProperty("publicKey").GetString() ?? "").Split(' ');
            if (parts.Length != 2) throw new InvalidDataException("Malformed pairing public key.");
            blob = Convert.FromBase64String(parts[1]);
            if (PublicLine(blob) != string.Join(' ', parts) || root.GetProperty("fingerprint").GetString() != Fingerprint(blob))
                throw new InvalidDataException("The pairing public key does not match the key type or fingerprint recorded in the file.");
        }
        authorizedKeys = Path.GetFullPath(authorizedKeys);
        hostKey = Path.GetFullPath(hostKey);
        var fingerprint = Fingerprint(blob);
        Console.Error.WriteLine($"Controller key to authorize: {fingerprint}\nAuthorized keys file: {authorizedKeys}");
        var already = File.Exists(authorizedKeys) && TcsCrypto.ReadAuthorizedKeys(authorizedKeys).Any(key => key.SequenceEqual(blob));
        if (!already || expected is not null) Confirm(fingerprint, expected);
        Deployment.EnsureSshDirectory(Path.GetDirectoryName(hostKey)!);
        using (var keyLock = new FileStream(hostKey + ".tcs-lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            Deployment.ValidatePair(hostKey);
            var hostBlob = TcsCrypto.PublicBlob(TcsCrypto.ReadPrivateKey(hostKey));
            Deployment.EnsureSshDirectory(Path.GetDirectoryName(authorizedKeys)!);
            using var authLock = new FileStream(authorizedKeys + ".tcs-lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var existing = File.Exists(authorizedKeys) ? File.ReadAllText(authorizedKeys) : "";
            if (!File.Exists(authorizedKeys) || !TcsCrypto.ReadAuthorizedKeys(authorizedKeys).Any(key => key.SequenceEqual(blob)))
                AtomicWrite(authorizedKeys, existing + (existing.Length > 0 && !existing.EndsWith('\n') ? "\n" : "") + PublicLine(blob) + "\n", true);
            Console.WriteLine($"Controller authorized.\nControlled PC host fingerprint: {Fingerprint(hostBlob)}\nVerify this fingerprint on the controller at the first connection; no receipt file is needed.\nStart the daemon: tcsd\nFixed data folder: {Deployment.Data}\nA running tcsd picks up the new key automatically.");
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
