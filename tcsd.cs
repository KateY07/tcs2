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
    List<byte[]> authorizedBlobs;
    DateTime authorizedStamp;
    readonly object authLock = new();
    readonly object auditLock = new();
    readonly Tcs.PairingServer pairing;
    readonly int pairSeconds;
    const long AuditRotateBytes = 5 * 1024 * 1024;
    static readonly AsyncLocal<string?> CurrentSource = new();

    // "tcsd pair" opens the window as soon as the listener is up.
    public bool OpenPairingOnStart { get; set; }
#if TCS_TESTING
    public string? FixedPairingCode { get; set; }
#endif

#if TCS_TESTING
    public tcsd(string authorizedKeysPath, string hostPrivateKeyPath, string? dataDirectory = null, int pairSeconds = Tcs.PairingServer.DefaultSeconds, int pairSilentSeconds = 60)
#else
    public tcsd()
#endif
    {
#if !TCS_TESTING
        var authorizedKeysPath = Tcs.Deployment.AuthorizedKeys;
        var hostPrivateKeyPath = Tcs.Deployment.HostKey;
        string? dataDirectory = null;
        var pairSeconds = Tcs.PairingServer.DefaultSeconds;
        var pairSilentSeconds = 60;
#endif
        this.pairSeconds = pairSeconds;
        this.authorizedKeysPath = authorizedKeysPath;
        this.hostPrivateKeyPath = hostPrivateKeyPath;
        var root = dataDirectory is null ? Tcs.Deployment.Data : Path.GetFullPath(dataDirectory);
        Directory.CreateDirectory(root);
        uploadsDirectory = Path.Combine(root, "uploads");
        Directory.CreateDirectory(uploadsDirectory);
        auditPath = Path.Combine(root, "tcs-audit.log");
        hostPrivate = TcsCrypto.ReadPrivateKey(hostPrivateKeyPath);
        hostBlob = TcsCrypto.PublicBlob(hostPrivate);
        authorizedBlobs = File.Exists(authorizedKeysPath) ? TcsCrypto.ReadAuthorizedKeys(authorizedKeysPath) : [];   // may be empty: pairing creates it
        authorizedStamp = File.GetLastWriteTimeUtc(authorizedKeysPath);
        pairing = new Tcs.PairingServer(hostBlob, AuthorizePairedKey, Audit, line => Console.Error.WriteLine("tcsd: " + line), pairSeconds, silentSeconds: pairSilentSeconds);
    }

    // Opens the one-time pairing window and tells the operator what to run on the controller.
    public (string Code, DateTimeOffset Expires) OpenPairingWindow(string? fixedDigits = null)
    {
        var (code, expires) = pairing.Open(fixedDigits);
        Console.Error.WriteLine($"tcsd: pairing code {code} (valid {Math.Max(1, (int)(expires - DateTimeOffset.UtcNow).TotalSeconds)} s, {Tcs.PairingServer.DefaultAttempts} attempts, single use)");
        Console.Error.WriteLine($"tcsd: on the controller run: tcs pair {Environment.MachineName} {code}");
        return (code, expires);
    }

    bool IsAuthorized(byte[] blob)
    {
        lock (authLock)
        {
            if (authorizedBlobs.Any(known => known.SequenceEqual(blob))) return true;
            ReloadAuthorizedIfChanged();   // a key imported or paired after start must work without a restart
            return authorizedBlobs.Any(known => known.SequenceEqual(blob));
        }
    }

    void ReloadAuthorizedIfChanged()
    {
        try
        {
            var stamp = File.GetLastWriteTimeUtc(authorizedKeysPath);
            if (stamp == authorizedStamp) return;
            authorizedBlobs = File.Exists(authorizedKeysPath) ? TcsCrypto.ReadAuthorizedKeys(authorizedKeysPath) : [];
            authorizedStamp = stamp;
            Audit("authorized-reload", null, "OK", $"keys={authorizedBlobs.Count}");
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or FormatException)
        {
            Audit("authorized-reload", null, "FAILED", exception.Message);
        }
    }

    // Called by the pairing window after the controller proved the code. Returns true if the key was already authorized.
    bool AuthorizePairedKey(byte[] blob)
    {
        lock (authLock)
        {
            ReloadAuthorizedIfChanged();
            if (authorizedBlobs.Any(known => known.SequenceEqual(blob))) return true;
            Tcs.Deployment.EnsureSshDirectory(Path.GetDirectoryName(authorizedKeysPath)!);
            using var fileLock = new FileStream(authorizedKeysPath + ".tcs-lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var existing = File.Exists(authorizedKeysPath) ? File.ReadAllText(authorizedKeysPath) : "";
            Tcs.Pairing.AtomicWrite(authorizedKeysPath, existing + (existing.Length > 0 && !existing.EndsWith('\n') ? "\n" : "") + Tcs.Pairing.PublicLine(blob) + "\n", true);
            authorizedBlobs = [.. authorizedBlobs, blob];
            authorizedStamp = File.GetLastWriteTimeUtc(authorizedKeysPath);
            return false;
        }
    }

    void Audit(string evt, string? fingerprint, string result, string? detail) =>
        WriteAudit(JsonSerializer.Serialize(new TcsEventAudit(DateTimeOffset.UtcNow, evt, CurrentSource.Value, fingerprint, result, detail), TcsJsonContext.Default.TcsEventAudit));

    public async Task RunAsync(IPAddress address, int port, CancellationToken cancellationToken = default)
    {
        var listener = new TcpListener(IPAddress.IPv6Any, port);
        listener.Server.DualMode = true;
        listener.Start();
        Audit("daemon-start", Tcs.Pairing.Fingerprint(hostBlob), "OK", $"port={port} keys={authorizedBlobs.Count}");
        Console.Error.WriteLine($"tcsd started: IPv4/IPv6 TCP {port}\nHost fingerprint: {Tcs.Pairing.Fingerprint(hostBlob)}\nAuthorized controller keys: {authorizedBlobs.Count}\nData folder: {Path.GetDirectoryName(auditPath)}\nPairing is off: it is only available after starting tcsd with 'tcsd pair'. Ctrl+C to stop.");
        if (OpenPairingOnStart)
        {
#if TCS_TESTING
            OpenPairingWindow(FixedPairingCode);
#else
            OpenPairingWindow();
#endif
        }
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
            client.NoDelay = true;
            var remote = (client.Client.RemoteEndPoint as IPEndPoint)?.Address ?? IPAddress.IPv6None;
            CurrentSource.Value = (remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote).ToString();
            await using var stream = client.GetStream();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serverCancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(60));
            try
            {
                var prefix = await TcsWire.ReadPrefixAsync(stream, timeout.Token);
                if (prefix.Type == Tcs.PairWire.HelloType)
                {
                    await pairing.HandleAsync(stream, remote, serverCancellation);
                    return;
                }
                var handshake = await HandshakeAsync(stream, prefix, timeout.Token);
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
                Console.Error.WriteLine($"tcsd: connection ended: {(serverCancellation.IsCancellationRequested ? "server stopping" : "handling took longer than 60 seconds")}; {exception.Message}");
            }
        }
    }

    async Task<(TcsWire.Session Session, string ClientFingerprint)?> HandshakeAsync(NetworkStream stream, (byte Type, ushort Version, ushort Cipher) prefix, CancellationToken cancellationToken)
    {
        var hello = await TcsWire.ReadClientHelloAsync(stream, cancellationToken, prefix);
        var clientKey = OpenSshPublicKeyUtilities.ParsePublicKey(hello.Blob);
        var clientFingerprint = Tcs.Pairing.Fingerprint(hello.Blob);
        if (!IsAuthorized(hello.Blob))
        {
            Audit("auth-denied", clientFingerprint, "NOT_AUTHORIZED", null);
            await TcsWire.WriteAllAsync(stream, TcsWire.BuildReject(TcsWire.RejectNotAuthorized, $"controller key {clientFingerprint} is not authorized on this computer"), cancellationToken);
            throw new CryptographicException($"client key is not authorized; controller fingerprint {clientFingerprint}. Pair it with tcsd pair, then retry.");
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
            Console.Error.WriteLine("tcsd: host identity sent; the peer closed before authenticating (probably a first-use fingerprint probe or a cancel). Nothing was authenticated, run or uploaded. This line does not mean pairing succeeded.");
            return null;
        }
        var clientSignature = await TcsWire.ReadClientAuthAsync(stream, cancellationToken, first[0]);
        var expected = TcsCrypto.HashLabel("TCS1/client", hello.Raw, serverHello);
        if (!TcsCrypto.Verify(clientKey, expected, clientSignature))
        {
            Audit("auth-denied", clientFingerprint, "BAD_SIGNATURE", null);
            throw new CryptographicException("invalid client signature");
        }
        var clientAuth = TcsWire.BuildClientAuth(clientSignature);
        var shared = TcsCrypto.Agree(serverEphemeral, hello.Ephemeral);
        var transcript = SHA256.HashData(hello.Raw.Concat(serverHello).Concat(clientAuth).ToArray());
        var session = new TcsWire.Session(TcsCrypto.Derive(shared, transcript), client: false);
        Audit("auth-ok", clientFingerprint, "OK", null);
        return (session, clientFingerprint);
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
            var result = await RunPythonAsync(scriptPath, TimeSpan.FromSeconds(request.TimeoutSeconds is > 0 ? request.TimeoutSeconds.Value : 30),
                request.MaxOutput is >= 0 ? request.MaxOutput.Value : Tcs.OutputCap.DefaultLimit, cancellationToken);
            started.Stop();
            WriteAudit(JsonSerializer.Serialize(
                new TcsExecAudit(DateTimeOffset.UtcNow, "/v1/exec", fingerprint, started.ElapsedMilliseconds, result.ExitCode, result.TimedOut, CurrentSource.Value, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(request.Script))).ToLowerInvariant()),
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
            new TcsUploadAudit(DateTimeOffset.UtcNow, "/v1/upload", fingerprint, new[] { stored }, CurrentSource.Value),
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

    async Task<ExecResult> RunPythonAsync(string scriptPath, TimeSpan timeout, int maxOutput, CancellationToken cancellationToken)
    {
        var elapsed = Stopwatch.StartNew();
        var startInfo = new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("TCS_PYTHON_EXE") is { Length: > 0 } configured ? configured : OperatingSystem.IsWindows() ? "python" : "python3",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add(scriptPath);
        using var process = new Process { StartInfo = startInfo };
        process.Start();
        var stdout = Tcs.OutputCap.ReadAsync(process.StandardOutput, maxOutput, cancellationToken);
        var stderr = Tcs.OutputCap.ReadAsync(process.StandardError, maxOutput, cancellationToken);
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
        var (outText, outOmitted) = await stdout;
        var (errText, errOmitted) = await stderr;
        return new ExecResult(timedOut ? null : process.ExitCode, outText, errText, timedOut, outOmitted, errOmitted, elapsed.ElapsedMilliseconds);
    }

    void WriteAudit(string line)
    {
        lock (auditLock)
        {
            var info = new FileInfo(auditPath);
            if (info.Exists && info.Length >= AuditRotateBytes)
                for (var index = 3; index >= 1; index--)   // tcs-audit.log -> .1 -> .2 -> .3 (oldest dropped)
                {
                    var from = index == 1 ? auditPath : auditPath + "." + (index - 1);
                    if (File.Exists(from)) File.Move(from, auditPath + "." + index, true);
                }
            File.AppendAllText(auditPath, line + Environment.NewLine);
        }
    }

    static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception exception) { Console.Error.WriteLine($"tcsd: failed to delete temporary script '{path}': {exception}"); }
    }

}
