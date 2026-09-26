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

#if TCS_TESTING
    public tcsd(string authorizedKeysPath, string hostPrivateKeyPath, string? dataDirectory = null)
#else
    public tcsd()
#endif
    {
#if !TCS_TESTING
        var authorizedKeysPath = Tcs.Deployment.AuthorizedKeys;
        var hostPrivateKeyPath = Tcs.Deployment.HostKey;
        string? dataDirectory = null;
#endif
        this.authorizedKeysPath = authorizedKeysPath;
        this.hostPrivateKeyPath = hostPrivateKeyPath;
        var root = dataDirectory is null ? Tcs.Deployment.Data : Path.GetFullPath(dataDirectory);
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
        var listener = new TcpListener(IPAddress.IPv6Any, port);
        listener.Server.DualMode = true;
        listener.Start();
        Console.Error.WriteLine($"被控端已启动：IPv4/IPv6 TCP {port}\n主机指纹：{Tcs.Pairing.Fingerprint(hostBlob)}\n已授权主控公钥：{authorizedBlobs.Count}\n数据目录：{Path.GetDirectoryName(auditPath)}\n按 Ctrl+C 停止。");
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
                if (handshake is null) return;
                var request = await ReadRequestAsync(stream, handshake.Value.Session, timeout.Token);
                var response = await HandleHttpAsync(request.HttpBytes, handshake.Value.ClientFingerprint, timeout.Token);
                for (var offset = 0; offset < response.Length;)
                {
                    var count = Math.Min(64 * 1024, response.Length - offset);
                    await TcsWire.WriteFrameAsync(stream, handshake.Value.Session, TcsWire.Data, 1, response.AsMemory(offset, count), timeout.Token);
                    offset += count;
                }
                await TcsWire.WriteFrameAsync(stream, handshake.Value.Session, TcsWire.End, 1, ReadOnlyMemory<byte>.Empty, timeout.Token);
            }
            catch (Exception exception) when (exception is IOException or SocketException or EndOfStreamException or CryptographicException or InvalidDataException)
            {
                Console.Error.WriteLine($"tcsd: connection rejected: {exception.Message}");
            }
            catch (OperationCanceledException exception)
            {
                Console.Error.WriteLine($"tcsd: connection ended: {(serverCancellation.IsCancellationRequested ? "服务停止" : "连接处理超过 60 秒")}；{exception.Message}");
            }
        }
    }

    async Task<(TcsWire.Session Session, string ClientFingerprint)?> HandshakeAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var hello = await TcsWire.ReadClientHelloAsync(stream, cancellationToken);
        var clientKey = OpenSshPublicKeyUtilities.ParsePublicKey(hello.Blob);
        if (!authorizedBlobs.Any(blob => blob.SequenceEqual(hello.Blob)))
        {
            throw new CryptographicException($"client key is not authorized；主控指纹 {Tcs.Pairing.Fingerprint(hello.Blob)}，请核对并导入正确的配对文件，重启 tcsd 加载授权。");
        }
        var (serverEphemeral, serverEphemeralPublic) = TcsCrypto.NewEphemeral();
        var serverNonce = RandomNumberGenerator.GetBytes(32);
        var unsigned = TcsWire.BuildServerHelloUnsigned(hostBlob, serverEphemeralPublic, serverNonce);
        var signature = TcsCrypto.Sign(hostPrivate, TcsCrypto.HashLabel("TCS1/server", hello.Raw, unsigned));
        var serverHello = TcsWire.BuildServerHello(unsigned, signature);
        await TcsWire.WriteAllAsync(stream, serverHello, cancellationToken);
        var first = new byte[1];
        if (await stream.ReadAsync(first, cancellationToken) == 0)
        {
            Console.Error.WriteLine("tcsd: 主机身份已发送，对端在认证前结束连接（可能为首次指纹探测或主动取消）；未认证，未执行指令或上传。此日志不表示配对已成功。");
            return null;
        }
        var clientSignature = await TcsWire.ReadClientAuthAsync(stream, cancellationToken, first[0]);
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
        var request = JsonSerializer.Deserialize(body, TcsJsonContext.Default.ExecRequest)
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
            WriteAudit(JsonSerializer.Serialize(
                new TcsExecAudit(DateTimeOffset.UtcNow, "/v1/exec", fingerprint, started.ElapsedMilliseconds, result.ExitCode, result.TimedOut),
                TcsJsonContext.Default.TcsExecAudit));
            return HttpResponse(200, "application/json", JsonSerializer.Serialize(result, TcsJsonContext.Default.ExecResult));
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
        WriteAudit(JsonSerializer.Serialize(
            new TcsUploadAudit(DateTimeOffset.UtcNow, "/v1/upload", fingerprint, new[] { stored }),
            TcsJsonContext.Default.TcsUploadAudit));
        return HttpResponse(200, "application/json", JsonSerializer.Serialize(
            new UploadResponse(new[] { stored }), TcsJsonContext.Default.UploadResponse));
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

    void WriteAudit(string line)
    {
        lock (auditLock)
        {
            File.AppendAllText(auditPath, line + Environment.NewLine);
        }
    }

    static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception exception) { Console.Error.WriteLine($"tcsd: failed to delete temporary script '{path}': {exception}"); }
    }

}
