using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;

static class TcsCrypto
{
    const int KeySize = 32;

    public static byte[] ReadPublicKeyBlob(string path)
    {
        var line = File.ReadLines(path)
            .Select(line => line.Trim())
            .FirstOrDefault(line => line.Length > 0 && !line.StartsWith('#'))
            ?? throw new InvalidDataException($"no public key in {path}");
        var fields = line.Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2 || fields.Length > 3 || fields[0].Contains('='))
        {
            throw new InvalidDataException($"invalid authorized key line in {path}");
        }
        if (fields[0] is not ("ssh-ed25519" or "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" or "ssh-rsa"))
        {
            throw new InvalidDataException($"unsupported public key type: {fields[0]}");
        }
        return Convert.FromBase64String(fields[1]);
    }

    public static List<byte[]> ReadAuthorizedKeys(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("authorized_keys not found", path);
        }
        var result = new List<byte[]>();
        foreach (var raw in File.ReadLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }
            var fields = line.Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length is < 2 or > 3 || fields[0].Contains('='))
            {
                throw new InvalidDataException("authorized_keys options are not supported");
            }
            result.Add(Convert.FromBase64String(fields[1]));
        }
        return result;
    }

    public static AsymmetricKeyParameter ReadPrivateKey(string path)
    {
        var text = File.ReadAllText(path);
        var begin = text.IndexOf("-----BEGIN OPENSSH PRIVATE KEY-----", StringComparison.Ordinal);
        var end = text.IndexOf("-----END OPENSSH PRIVATE KEY-----", StringComparison.Ordinal);
        if (begin < 0 || end <= begin)
        {
            throw new InvalidDataException("an OpenSSH private key is required");
        }
        var bodyStart = begin + "-----BEGIN OPENSSH PRIVATE KEY-----".Length;
        var body = text[bodyStart..end].Replace("\r", "").Replace("\n", "").Trim();
        return OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob(Convert.FromBase64String(body));
    }

    public static byte[] PublicBlob(AsymmetricKeyParameter key) => OpenSshPublicKeyUtilities.EncodePublicKey(PublicKey(key));

    static AsymmetricKeyParameter PublicKey(AsymmetricKeyParameter key) => key switch
    {
        Ed25519PrivateKeyParameters ed => ed.GeneratePublicKey(),
        RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
        ECPrivateKeyParameters ec => new ECPublicKeyParameters(ec.Parameters.G.Multiply(ec.D).Normalize(), ec.Parameters),
        _ when !key.IsPrivate => key,
        _ => throw new NotSupportedException($"unsupported key type: {key.GetType().Name}")
    };

    public static byte[] Sign(AsymmetricKeyParameter key, byte[] data)
    {
        var signer = CreateSigner(key);
        signer.Init(true, key);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    public static bool Verify(AsymmetricKeyParameter key, byte[] data, byte[] signature)
    {
        var signer = CreateSigner(key);
        signer.Init(false, key);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }

    static ISigner CreateSigner(AsymmetricKeyParameter key) => key switch
    {
        Ed25519PrivateKeyParameters or Ed25519PublicKeyParameters => new Ed25519Signer(),
        RsaKeyParameters => SignerUtilities.GetSigner("SHA-256withRSA"),
        ECPublicKeyParameters ec => SignerUtilities.GetSigner($"SHA-{ec.Parameters.Curve.FieldSize}withECDSA"),
        ECPrivateKeyParameters ec => SignerUtilities.GetSigner($"SHA-{ec.Parameters.Curve.FieldSize}withECDSA"),
        _ => throw new NotSupportedException($"unsupported signing key: {key.GetType().Name}")
    };

    public static (X25519PrivateKeyParameters Private, byte[] Public) NewEphemeral()
    {
        var bytes = RandomNumberGenerator.GetBytes(KeySize);
        var key = new X25519PrivateKeyParameters(bytes, 0);
        return (key, key.GeneratePublicKey().GetEncoded());
    }

    public static byte[] Agree(X25519PrivateKeyParameters key, byte[] publicKey)
    {
        var result = new byte[KeySize];
        key.GenerateSecret(new X25519PublicKeyParameters(publicKey, 0), result, 0);
        return result;
    }

    public static byte[] Derive(byte[] shared, byte[] transcript)
    {
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 72, transcript, Encoding.ASCII.GetBytes("TCS1/session"));
    }

    public static byte[] Fingerprint(byte[] publicBlob) => SHA256.HashData(publicBlob);

    public static byte[] HashLabel(string label, params byte[][] parts)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.ASCII.GetBytes(label));
        foreach (var part in parts)
        {
            hash.AppendData(part);
        }
        return hash.GetHashAndReset();
    }

    public static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
        return result;
    }
}
