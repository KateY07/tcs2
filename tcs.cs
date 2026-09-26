using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;

public sealed class tcs
{
    readonly string host;
    readonly int port;
    readonly string privateKeyPath;
    readonly string serverPublicKeyPath;

    public tcs(string host, int port, string privateKeyPath, string serverPublicKeyPath)
    {
        this.host = host;
        this.port = port;
        this.privateKeyPath = privateKeyPath;
        this.serverPublicKeyPath = serverPublicKeyPath;
    }

    public async Task<JsonElement> ExecAsync(string script, int timeoutSeconds = 30, CancellationToken cancellationToken = default)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(
            new ClientExecRequest(script, timeoutSeconds),
            TcsJsonContext.Default.ClientExecRequest);
        var response = await RequestAsync(BuildRequest("POST", "/v1/exec", "application/json", body), cancellationToken);
        EnsureSuccess(response);
        return JsonDocument.Parse(response.Body).RootElement.Clone();
    }

    public async Task<JsonElement> UploadAsync(string fileName, byte[] content, CancellationToken cancellationToken = default)
    {
        var boundary = "----TCS" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
        var prefix = Encoding.UTF8.GetBytes($"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{Path.GetFileName(fileName)}\"\r\nContent-Type: application/octet-stream\r\n\r\n");
        var suffix = Encoding.UTF8.GetBytes($"\r\n--{boundary}--\r\n");
        var body = new byte[prefix.Length + content.Length + suffix.Length];
        prefix.CopyTo(body, 0);
        content.CopyTo(body, prefix.Length);
        suffix.CopyTo(body, prefix.Length + content.Length);
        var response = await RequestAsync(BuildRequest("POST", "/v1/upload", $"multipart/form-data; boundary={boundary}", body), cancellationToken);
        EnsureSuccess(response);
        return JsonDocument.Parse(response.Body).RootElement.Clone();
    }

    public async Task<JsonElement> HealthAsync(CancellationToken cancellationToken = default)
    {
        var response = await RequestAsync(BuildRequest("GET", "/v1/health", null, Array.Empty<byte>()), cancellationToken);
        EnsureSuccess(response);
        return JsonDocument.Parse(response.Body).RootElement.Clone();
    }

    async Task<Response> RequestAsync(byte[] request, CancellationToken cancellationToken)
    {
        using var tcp = new TcpClient(AddressFamily.InterNetworkV6);
        tcp.Client.DualMode = true;
        await tcp.ConnectAsync(host, port, cancellationToken);
        await using var stream = tcp.GetStream();
        var session = await HandshakeAsync(stream, cancellationToken);
        await TcsWire.WriteFrameAsync(stream, session, TcsWire.Open, 1, new byte[] { 1, 0 }, cancellationToken);
        for (var offset = 0; offset < request.Length;)
        {
            var count = Math.Min(64 * 1024, request.Length - offset);
            await TcsWire.WriteFrameAsync(stream, session, TcsWire.Data, 1, request.AsMemory(offset, count), cancellationToken);
            offset += count;
        }
        await TcsWire.WriteFrameAsync(stream, session, TcsWire.End, 1, ReadOnlyMemory<byte>.Empty, cancellationToken);

        using var response = new MemoryStream();
        while (true)
        {
            var frame = await TcsWire.ReadFrameAsync(stream, session, cancellationToken);
            if (frame.StreamId != 1)
            {
                throw new InvalidDataException("unexpected stream id");
            }
            if (frame.Type == TcsWire.Data)
            {
                response.Write(frame.Payload);
            }
            else if (frame.Type == TcsWire.End)
            {
                return ParseResponse(response.ToArray());
            }
            else if (frame.Type == TcsWire.Error || frame.Type == TcsWire.Reset)
            {
                throw new IOException(Encoding.UTF8.GetString(frame.Payload));
            }
            else
            {
                throw new InvalidDataException($"unexpected frame type: {frame.Type}");
            }
        }
    }

    async Task<TcsWire.Session> HandshakeAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var clientPrivate = TcsCrypto.ReadPrivateKey(privateKeyPath);
        var clientBlob = TcsCrypto.PublicBlob(clientPrivate);
        var expectedServerBlob = TcsCrypto.ReadPublicKeyBlob(serverPublicKeyPath);
        var (clientEphemeral, clientEphemeralPublic) = TcsCrypto.NewEphemeral();
        var clientNonce = RandomNumberGenerator.GetBytes(32);
        var clientHello = TcsWire.BuildClientHello(clientBlob, clientEphemeralPublic, clientNonce);
        await TcsWire.WriteAllAsync(stream, clientHello, cancellationToken);

        var serverHello = await TcsWire.ReadServerHelloAsync(stream, cancellationToken);
        if (!serverHello.Blob.SequenceEqual(expectedServerBlob))
        {
            throw new CryptographicException("server host-key fingerprint mismatch");
        }
        VerifyServerSignature(clientHello, serverHello.Blob, serverHello.Raw, serverHello.Signature);

        var clientSignature = TcsCrypto.Sign(clientPrivate, TcsCrypto.HashLabel("TCS1/client", clientHello, serverHello.Raw));
        var clientAuth = TcsWire.BuildClientAuth(clientSignature);
        await TcsWire.WriteAllAsync(stream, clientAuth, cancellationToken);
        var shared = TcsCrypto.Agree(clientEphemeral, serverHello.Ephemeral);
        var transcript = SHA256.HashData(clientHello.Concat(serverHello.Raw).Concat(clientAuth).ToArray());
        return new TcsWire.Session(TcsCrypto.Derive(shared, transcript), client: true);
    }

    public static async Task<byte[]> InspectServerKeyAsync(string host, int port, string privateKeyPath, CancellationToken cancellationToken = default)
    {
        var clientBlob = TcsCrypto.PublicBlob(TcsCrypto.ReadPrivateKey(privateKeyPath));
        var (_, ephemeral) = TcsCrypto.NewEphemeral();
        var hello = TcsWire.BuildClientHello(clientBlob, ephemeral, RandomNumberGenerator.GetBytes(32));
        using var tcp = new TcpClient(AddressFamily.InterNetworkV6);
        tcp.Client.DualMode = true;
        await tcp.ConnectAsync(host, port, cancellationToken);
        await using var stream = tcp.GetStream();
        await TcsWire.WriteAllAsync(stream, hello, cancellationToken);
        var server = await TcsWire.ReadServerHelloAsync(stream, cancellationToken);
        VerifyServerSignature(hello, server.Blob, server.Raw, server.Signature);
        return server.Blob;
    }

    static void VerifyServerSignature(byte[] clientHello, byte[] blob, byte[] raw, byte[] signature)
    {
        var serverPublic = Org.BouncyCastle.Crypto.Utilities.OpenSshPublicKeyUtilities.ParsePublicKey(blob);
        var unsigned = raw[..^(4 + signature.Length)];
        if (!TcsCrypto.Verify(serverPublic, TcsCrypto.HashLabel("TCS1/server", clientHello, unsigned), signature))
            throw new CryptographicException("invalid server signature");
    }

    static byte[] BuildRequest(string method, string path, string? contentType, byte[] body)
    {
        var headers = new StringBuilder()
            .Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\n")
            .Append("Host: tcs\r\n")
            .Append("Connection: close\r\n")
            .Append("Content-Length: ").Append(body.Length).Append("\r\n");
        if (contentType is not null)
        {
            headers.Append("Content-Type: ").Append(contentType).Append("\r\n");
        }
        var head = Encoding.ASCII.GetBytes(headers.Append("\r\n").ToString());
        return head.Concat(body).ToArray();
    }

    static Response ParseResponse(byte[] bytes)
    {
        var separator = Encoding.ASCII.GetBytes("\r\n\r\n");
        var index = bytes.AsSpan().IndexOf(separator);
        if (index < 0)
        {
            throw new InvalidDataException("malformed HTTP response");
        }
        var headerEnd = index + separator.Length;
        var headers = Encoding.ASCII.GetString(bytes, 0, index).Split("\r\n");
        var status = int.Parse(headers[0].Split(' ')[1]);
        return new Response(status, bytes[headerEnd..]);
    }

    static void EnsureSuccess(Response response)
    {
        if (response.StatusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException($"HTTP request failed with status {response.StatusCode}: {Encoding.UTF8.GetString(response.Body)}");
        }
    }

    sealed record Response(int StatusCode, byte[] Body);
}
