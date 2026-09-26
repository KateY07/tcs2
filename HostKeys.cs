using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace Tcs;

internal static class HostKeys
{
    internal static void CreateOrExport(string path)
    {
        path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (!File.Exists(path))
        {
            var key = new Ed25519PrivateKeyParameters(RandomNumberGenerator.GetBytes(32), 0);
            var encoded = OpenSshPrivateKeyUtilities.EncodePrivateKey(key);
            var pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                Convert.ToBase64String(encoded, Base64FormattingOptions.InsertLineBreaks) +
                "\n-----END OPENSSH PRIVATE KEY-----\n";
            using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            file.Write(Encoding.ASCII.GetBytes(pem));
        }
        var blob = TcsCrypto.PublicBlob(TcsCrypto.ReadPrivateKey(path));
        var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(blob);
        var type = Encoding.ASCII.GetString(blob, 4, length);
        File.WriteAllText(path + ".pub", $"{type} {Convert.ToBase64String(blob)} tcs-host\n", Encoding.ASCII);
        Console.WriteLine("SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('='));
    }
}
