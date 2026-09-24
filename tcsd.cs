using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;

public sealed class tcsd
{
    readonly string authorizedKeysPath;
    readonly string hostPrivateKeyPath;
    readonly string uploadsDirectory;
    readonly string auditPath;
    readonly AsymmetricKeyParameter hostPrivate;
    readonly byte[] hostBlob;
    readonly List<byte[]> authorizedBlobs;
    readonly object auditLock = new();

    public tcsd(string authorizedKeysPath, string hostPrivateKeyPath, string? dataDirectory = null)
    {
        this.authorizedKeysPath = authorizedKeysPath;
        this.hostPrivateKeyPath = hostPrivateKeyPath;
        var root = dataDirectory is null ? AppContext.BaseDirectory : Path.GetFullPath(dataDirectory);
        Directory.CreateDirectory(root);
        uploadsDirectory = Path.Combine(root, "uploads");
        Directory.CreateDirectory(uploadsDirectory);
        auditPath = Path.Combine(root, "tcs-audit.log");
        hostPrivate = TcsCrypto.ReadPrivateKey(hostPrivateKeyPath);
        hostBlob = TcsCrypto.PublicBlob(hostPrivate);
        authorizedBlobs = TcsCrypto.ReadAuthorizedKeys(authorizedKeysPath);
    }

    public async Task RunAsync(IPAddress address, int port, CancellationToken cancellationToken = default)
    {
        var listener = new TcpListener(address, port);
        listener.Start();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(cancellationToken);
                _ = HandleClientAsync(client, cancellationToken);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    async Task HandleClientAsync(TcpClient client, CancellationToken serverCancellation)
    {
        using (client)
        {
            await using var stream = client.GetStream();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serverCancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(60));
            try
            {
                var handshake = await HandshakeAsync(stream, timeout.Token);
                var request = await ReadRequestAsync(stream, handshake.Session, timeout.Token);
                var response = await HandleHttpAsync(request.HttpBytes, handshake.ClientFingerprint, timeout.Token);
                for (var offset = 0; offset < response.Length;)
                {
                    var count = Math.Min(64 * 1024, response.Length - offset);
                    await TcsWire.WriteFrameAsync(stream, handshake.Session, TcsWire.Data, 1, response.AsMemory(offset, count), timeout.Token);
                    offset += count;
                }
                await TcsWire.WriteFrameAsync(stream, handshake.Session, TcsWire.End, 1, ReadOnlyMemory<byte>.Empty, timeout.Token);
            }
            catch (Exception exception) when (exception is IOException or SocketException or EndOfStreamException or CryptographicException or InvalidDataException)
            {
                Console.Error.WriteLine($"tcsd: connection rejected: {exception.Message}");
            }
        }
    }

    async Task<(TcsWire.Session Session, string ClientFingerprint)> HandshakeAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var hello = await TcsWire.ReadClientHelloAsync(stream, cancellationToken);
        var clientKey = OpenSshPublicKeyUtilities.ParsePublicKey(hello.Blob);
        if (!authorizedBlobs.Any(blob => blob.SequenceEqual(hello.Blob)))
        {
            throw new CryptographicException("client key is not authorized");
        }
        var (serverEphemeral, serverEphemeralPublic) = TcsCrypto.NewEphemeral();
        var serverNonce = RandomNumberGenerator.GetBytes(32);
        var unsigned = TcsWire.BuildServerHelloUnsigned(hostBlob, serverEphemeralPublic, serverNonce);
        var signature = TcsCrypto.Sign(hostPrivate, TcsCrypto.HashLabel("TCS1/server", hello.Raw, unsigned));
        var serverHello = TcsWire.BuildServerHello(unsigned, signature);
        await TcsWire.WriteAllAsync(stream, serverHello, cancellationToken);
        var clientSignature = await TcsWire.ReadClientAuthAsync(stream, cancellationToken);
        var expected = TcsCrypto.HashLabel("TCS1/client", hello.Raw, serverHello);
        if (!TcsCrypto.Verify(clientKey, expected, clientSignature))
        {
            throw new CryptographicException("invalid client signature");
        }
        var clientAuth = TcsWire.BuildClientAuth(clientSignature);
        var shared = TcsCrypto.Agree(serverEphemeral, hello.Ephemeral);
        var transcript = SHA256.HashData(hello.Raw.Concat(serverHello).Concat(clientAuth).ToArray());
        var session = new TcsWire.Session(TcsCrypto.Derive(shared, transcript), client: false);
        return (session, Convert.ToHexString(TcsCrypto.Fingerprint(hello.Blob)));
    }

    static async Task<(byte[] HttpBytes, uint StreamId)> ReadRequestAsync(NetworkStream stream, TcsWire.Session session, CancellationToken cancellationToken)
    {
        using var request = new MemoryStream();
        var opened = false;
        while (true)
        {
            var frame = await TcsWire.ReadFrameAsync(stream, session, cancellationToken);
            if (frame.StreamId != 1)
            {
                throw new InvalidDataException("unexpected stream id");
            }
            if (frame.Type == TcsWire.Open)
            {
                if (opened || frame.Payload.Length != 2 || frame.Payload[0] != 1 || frame.Payload[1] != 0)
                {
                    throw new InvalidDataException("invalid OPEN frame");
                }
                opened = true;
            }
            else if (frame.Type == TcsWire.Data && opened)
            {
                request.Write(frame.Payload);
            }
            else if (frame.Type == TcsWire.End && opened)
            {
                return (request.ToArray(), 1);
            }
            else
            {
                throw new InvalidDataException("invalid request frame sequence");
            }
        }
    }

    async Task<byte[]> HandleHttpAsync(byte[] request, string clientFingerprint, CancellationToken cancellationToken)
    {
        var split = FindHeaderEnd(request);
        if (split < 0)
        {
            return HttpResponse(400, "text/plain", "malformed HTTP request");
        }
        var headerText = Encoding.ASCII.GetString(request, 0, split);
        var lines = headerText.Split("\r\n");
        var requestLine = lines[0].Split(' ', 3);
        if (requestLine.Length != 3)
        {
            return HttpResponse(400, "text/plain", "malformed request line");
        }
        var headers = lines.Skip(1)
            .Select(line => line.Split(':', 2))
            .Where(parts => parts.Length == 2)
            .ToDictionary(parts => parts[0].Trim(), parts => parts[1].Trim(), StringComparer.OrdinalIgnoreCase);
        var body = request[(split + 4)..];
        var method = requestLine[0];
        var path = requestLine[1];
        byte[] response;
        if (method == "GET" && path == "/v1/health")
        {
            response = HttpResponse(200, "application/json", "{\"status\":\"ok\"}");
        }
        else if (method == "POST" && path == "/v1/exec")
        {
            response = await ExecAsync(body, clientFingerprint, cancellationToken);
        }
        else if (method == "POST" && path == "/v1/upload")
        {
            response = await UploadAsync(body, headers, clientFingerprint, cancellationToken);
        }
        else
        {
            response = HttpResponse(404, "application/json", "{\"error\":\"not found\"}");
        }
        return response;
    }

    async Task<byte[]> ExecAsync(byte[] body, string fingerprint, CancellationToken cancellationToken)
    {
        var request = JsonSerializer.Deserialize<ExecRequest>(body, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        })
            ?? throw new InvalidDataException("invalid exec JSON");
        if (string.IsNullOrEmpty(request.Script))
        {
            return HttpResponse(400, "application/json", "{\"error\":\"script must be a non-empty string\"}");
        }
        var scriptPath = Path.Combine(Path.GetTempPath(), "tcs", $"{Guid.NewGuid():N}.py");
        Directory.CreateDirectory(Path.GetDirectoryName(scriptPath)!);
        await File.WriteAllTextAsync(scriptPath, request.Script, Encoding.UTF8, cancellationToken);
        var started = Stopwatch.StartNew();
        try
        {
            var result = await RunPythonAsync(scriptPath, TimeSpan.FromSeconds(request.TimeoutSeconds is > 0 ? request.TimeoutSeconds.Value : 30), cancellationToken);
            started.Stop();
            WriteAudit(new { timestamp = DateTimeOffset.UtcNow, endpoint = "/v1/exec", clientFingerprint = fingerprint, durationMs = started.ElapsedMilliseconds, result.ExitCode, result.TimedOut });
            return HttpResponse(200, "application/json", JsonSerializer.Serialize(result));
        }
        finally
        {
            TryDelete(scriptPath);
        }
    }

    async Task<byte[]> UploadAsync(byte[] body, Dictionary<string, string> headers, string fingerprint, CancellationToken cancellationToken)
    {
        if (!headers.TryGetValue("Content-Type", out var contentType) || !contentType.Contains("boundary=", StringComparison.OrdinalIgnoreCase))
        {
            return HttpResponse(400, "application/json", "{\"error\":\"expected multipart/form-data\"}");
        }
        var boundary = contentType[(contentType.IndexOf("boundary=", StringComparison.OrdinalIgnoreCase) + 9)..].Trim(' ', '"');
        var marker = Encoding.UTF8.GetBytes("--" + boundary);
        var start = IndexOf(body, marker, 0);
        var headerEnd = IndexOf(body, Encoding.UTF8.GetBytes("\r\n\r\n"), start);
        if (start < 0 || headerEnd < 0)
        {
            return HttpResponse(400, "application/json", "{\"error\":\"malformed multipart body\"}");
        }
        var partHeaders = Encoding.UTF8.GetString(body, start, headerEnd - start);
        var filename = "upload.bin";
        var filenameMarker = "filename=\"";
        var filenameStart = partHeaders.IndexOf(filenameMarker, StringComparison.OrdinalIgnoreCase);
        if (filenameStart >= 0)
        {
            var end = partHeaders.IndexOf('"', filenameStart + filenameMarker.Length);
            if (end > filenameStart)
            {
                filename = Path.GetFileName(partHeaders[(filenameStart + filenameMarker.Length)..end]);
            }
        }
        var dataStart = headerEnd + 4;
        var endMarker = Encoding.UTF8.GetBytes("\r\n--" + boundary);
        var dataEnd = IndexOf(body, endMarker, dataStart);
        if (dataEnd < 0)
        {
            return HttpResponse(400, "application/json", "{\"error\":\"multipart terminator missing\"}");
        }
        var stored = $"{DateTimeOffset.UtcNow:yyyyMMddTHHmmssZ}_{Guid.NewGuid():N}_{filename}";
        await File.WriteAllBytesAsync(Path.Combine(uploadsDirectory, stored), body[dataStart..dataEnd], cancellationToken);
        WriteAudit(new { timestamp = DateTimeOffset.UtcNow, endpoint = "/v1/upload", clientFingerprint = fingerprint, files = new[] { stored } });
        return HttpResponse(200, "application/json", JsonSerializer.Serialize(new { saved = new[] { stored } }));
    }

    static byte[] HttpResponse(int status, string contentType, string body)
    {
        var data = Encoding.UTF8.GetBytes(body);
        var text = $"HTTP/1.1 {status} {(status == 200 ? "OK" : "Bad Request")}\r\nContent-Type: {contentType}\r\nContent-Length: {data.Length}\r\nConnection: close\r\n\r\n";
        return Encoding.ASCII.GetBytes(text).Concat(data).ToArray();
    }

    static int FindHeaderEnd(byte[] data) => IndexOf(data, Encoding.ASCII.GetBytes("\r\n\r\n"), 0);

    static int IndexOf(byte[] data, byte[] needle, int start)
    {
        for (var i = Math.Max(0, start); i <= data.Length - needle.Length; i++)
        {
            if (data.AsSpan(i, needle.Length).SequenceEqual(needle))
            {
                return i;
            }
        }
        return -1;
    }

    async Task<ExecResult> RunPythonAsync(string scriptPath, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("TCS_PYTHON_EXE") is { Length: > 0 } configured ? configured : "python",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add(scriptPath);
        using var process = new Process { StartInfo = startInfo };
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            timedOut = true;
            process.Kill(entireProcessTree: true);
        }
        return new ExecResult(timedOut ? null : process.ExitCode, await stdout, await stderr, timedOut);
    }

    void WriteAudit(object entry)
    {
        lock (auditLock)
        {
            File.AppendAllText(auditPath, JsonSerializer.Serialize(entry) + Environment.NewLine);
        }
    }

    static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception exception) { Console.Error.WriteLine($"tcsd: failed to delete temporary script '{path}': {exception}"); }
    }

    record ExecRequest(string Script, int? TimeoutSeconds);
    record ExecResult(int? ExitCode, string Stdout, string Stderr, bool TimedOut);
}
