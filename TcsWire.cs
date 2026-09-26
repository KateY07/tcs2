using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;

static class TcsWire
{
    public const byte Open = 0x10;
    public const byte Data = 0x11;
    public const byte End = 0x12;
    public const byte Reset = 0x13;
    public const byte Error = 0x14;
    public const int HeaderLength = 14;
    public const int TagLength = 16;
    public const int MaxCiphertext = 64 * 1024 + TagLength;

    public static async Task ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
        }
    }

    public static async Task WriteAllAsync(Stream stream, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(data, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    public static byte[] BuildClientHello(byte[] clientBlob, byte[] ephemeral, byte[] nonce)
    {
        using var output = new MemoryStream();
        WritePrefix(output, 0x01);
        WriteU16(output, 1);
        WriteU16(output, 1);
        WriteBytes(output, clientBlob);
        output.Write(ephemeral);
        output.Write(nonce);
        return output.ToArray();
    }

    public static byte[] BuildServerHelloUnsigned(byte[] serverBlob, byte[] ephemeral, byte[] nonce)
    {
        using var output = new MemoryStream();
        WritePrefix(output, 0x02);
        WriteU16(output, 1);
        WriteU16(output, 1);
        WriteBytes(output, serverBlob);
        output.Write(ephemeral);
        output.Write(nonce);
        return output.ToArray();
    }

    public static byte[] BuildServerHello(byte[] unsigned, byte[] signature)
    {
        using var output = new MemoryStream();
        output.Write(unsigned);
        WriteU32(output, (uint)signature.Length);
        output.Write(signature);
        return output.ToArray();
    }

    public static byte[] BuildClientAuth(byte[] signature)
    {
        using var output = new MemoryStream();
        WritePrefix(output, 0x03);
        WriteU32(output, (uint)signature.Length);
        output.Write(signature);
        return output.ToArray();
    }

    public static async Task<(byte[] Blob, byte[] Ephemeral, byte[] Nonce, byte[] Raw)> ReadClientHelloAsync(Stream stream, CancellationToken cancellationToken)
    {
        var prefix = await ReadPrefixAsync(stream, cancellationToken);
        if (prefix.Type != 0x01 || prefix.Version != 1 || prefix.Cipher != 1)
        {
            throw new InvalidDataException("invalid ClientHello");
        }
        var blob = await ReadBytesAsync(stream, cancellationToken);
        var ephemeral = new byte[32];
        var nonce = new byte[32];
        await ReadExactAsync(stream, ephemeral, cancellationToken);
        await ReadExactAsync(stream, nonce, cancellationToken);
        using var raw = new MemoryStream();
        WritePrefix(raw, 0x01);
        WriteU16(raw, 1);
        WriteU16(raw, 1);
        WriteBytes(raw, blob);
        raw.Write(ephemeral);
        raw.Write(nonce);
        return (blob, ephemeral, nonce, raw.ToArray());
    }

    public static async Task<(byte[] Blob, byte[] Ephemeral, byte[] Nonce, byte[] Signature, byte[] Raw)> ReadServerHelloAsync(Stream stream, CancellationToken cancellationToken)
    {
        var prefix = await ReadPrefixAsync(stream, cancellationToken);
        if (prefix.Type != 0x02 || prefix.Version != 1 || prefix.Cipher != 1)
        {
            throw new InvalidDataException("invalid ServerHello");
        }
        var blob = await ReadBytesAsync(stream, cancellationToken);
        var ephemeral = new byte[32];
        var nonce = new byte[32];
        await ReadExactAsync(stream, ephemeral, cancellationToken);
        await ReadExactAsync(stream, nonce, cancellationToken);
        var signature = await ReadBytesAsync(stream, cancellationToken);
        using var unsigned = new MemoryStream();
        WritePrefix(unsigned, 0x02);
        WriteU16(unsigned, 1);
        WriteU16(unsigned, 1);
        WriteBytes(unsigned, blob);
        unsigned.Write(ephemeral);
        unsigned.Write(nonce);
        using var raw = new MemoryStream();
        raw.Write(unsigned.ToArray());
        WriteU32(raw, (uint)signature.Length);
        raw.Write(signature);
        return (blob, ephemeral, nonce, signature, raw.ToArray());
    }

    public static async Task<byte[]> ReadClientAuthAsync(Stream stream, CancellationToken cancellationToken, byte? firstByte = null)
    {
        var prefix = new byte[5];
        if (firstByte is { } value)
        {
            prefix[0] = value;
            await ReadExactAsync(stream, prefix.AsMemory(1), cancellationToken);
        }
        else await ReadExactAsync(stream, prefix, cancellationToken);
        if (!prefix[..4].SequenceEqual(Encoding.ASCII.GetBytes("TCS1")) || prefix[4] != 0x03)
        {
            throw new InvalidDataException("invalid ClientAuth");
        }
        return await ReadBytesAsync(stream, cancellationToken);
    }

    public static async Task WriteFrameAsync(Stream stream, Session session, byte type, uint streamId, ReadOnlyMemory<byte> plaintext, CancellationToken cancellationToken)
    {
        if (plaintext.Length > 64 * 1024)
        {
            throw new InvalidDataException("frame payload is too large");
        }
        var sequence = session.NextSendSequence();
        var header = new byte[HeaderLength];
        header[0] = type;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(2, 4), streamId);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(6, 8), sequence);
        var ciphertext = new byte[plaintext.Length + TagLength];
        session.Encrypt(sequence, header, plaintext.Span, ciphertext);
        var frameLength = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(frameLength, (uint)(header.Length + ciphertext.Length));
        await stream.WriteAsync(frameLength, cancellationToken);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(ciphertext, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    public static async Task<Frame> ReadFrameAsync(Stream stream, Session session, CancellationToken cancellationToken)
    {
        var lengthBytes = new byte[4];
        await ReadExactAsync(stream, lengthBytes, cancellationToken);
        var length = BinaryPrimitives.ReadUInt32BigEndian(lengthBytes);
        if (length < HeaderLength + TagLength || length > HeaderLength + MaxCiphertext)
        {
            throw new InvalidDataException("invalid frame length");
        }
        var header = new byte[HeaderLength];
        await ReadExactAsync(stream, header, cancellationToken);
        var ciphertext = new byte[length - HeaderLength];
        await ReadExactAsync(stream, ciphertext, cancellationToken);
        var sequence = BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(6, 8));
        var plaintext = new byte[ciphertext.Length - TagLength];
        session.Decrypt(sequence, header, ciphertext, plaintext);
        return new Frame(header[0], BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(2, 4)), plaintext);
    }

    static void WritePrefix(Stream output, byte type)
    {
        output.Write(Encoding.ASCII.GetBytes("TCS1"));
        output.WriteByte(type);
    }

    static void WriteBytes(Stream output, byte[] data)
    {
        WriteU32(output, (uint)data.Length);
        output.Write(data);
    }

    static void WriteU16(Stream output, ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        output.Write(bytes);
    }

    static void WriteU32(Stream output, uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        output.Write(bytes);
    }

    static async Task<(byte Type, ushort Version, ushort Cipher)> ReadPrefixAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bytes = new byte[9];
        await ReadExactAsync(stream, bytes, cancellationToken);
        if (!bytes[..4].SequenceEqual(Encoding.ASCII.GetBytes("TCS1")))
        {
            throw new InvalidDataException("invalid TCS magic");
        }
        return (bytes[4], BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(5, 2)), BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(7, 2)));
    }

    static async Task<byte[]> ReadBytesAsync(Stream stream, CancellationToken cancellationToken)
    {
        var lengthBytes = new byte[4];
        await ReadExactAsync(stream, lengthBytes, cancellationToken);
        var length = BinaryPrimitives.ReadUInt32BigEndian(lengthBytes);
        if (length == 0 || length > 64 * 1024)
        {
            throw new InvalidDataException("invalid handshake field length");
        }
        var value = new byte[length];
        await ReadExactAsync(stream, value, cancellationToken);
        return value;
    }

    public sealed record Frame(byte Type, uint StreamId, byte[] Payload);

    public sealed class Session
    {
        readonly byte[] sendKey;
        readonly byte[] receiveKey;
        readonly byte[] sendPrefix;
        readonly byte[] receivePrefix;
        ulong sendSequence;
        ulong receiveSequence;

        public Session(byte[] keyMaterial, bool client)
        {
            sendKey = keyMaterial[(client ? 0 : 32)..(client ? 32 : 64)];
            receiveKey = keyMaterial[(client ? 32 : 0)..(client ? 64 : 32)];
            sendPrefix = keyMaterial[(client ? 64 : 68)..(client ? 68 : 72)];
            receivePrefix = keyMaterial[(client ? 68 : 64)..(client ? 72 : 68)];
        }

        public ulong NextSendSequence() => sendSequence++;

        public void Encrypt(ulong sequence, byte[] aad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
        {
            using var cipher = new ChaCha20Poly1305(sendKey);
            cipher.Encrypt(Nonce(sendPrefix, sequence), plaintext, ciphertext[..^TagLength], ciphertext[^TagLength..], aad);
        }

        public void Decrypt(ulong sequence, byte[] aad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
        {
            if (sequence != receiveSequence++)
            {
                throw new InvalidDataException("replayed or out-of-order frame");
            }
            using var cipher = new ChaCha20Poly1305(receiveKey);
            cipher.Decrypt(Nonce(receivePrefix, sequence), ciphertext[..^TagLength], ciphertext[^TagLength..], plaintext, aad);
        }

        static byte[] Nonce(byte[] prefix, ulong sequence)
        {
            var nonce = new byte[12];
            prefix.CopyTo(nonce, 0);
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), sequence);
            return nonce;
        }
    }
}
