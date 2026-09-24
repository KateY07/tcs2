// tcs: a small mTLS-authenticated HTTP ops endpoint.
//
// Usage:
//   tcs.exe -i <keydir> -p <port>
//
// <keydir> must contain:
//   server.crt              PEM server certificate (presented to clients)
//   server.key              PEM server private key
//   authorized-clients.json JSON array of SHA-256 client-certificate
//                           thumbprints (hex, case-insensitive) that are
//                           allowed to connect -- this is the trust model,
//                           equivalent to SSH's authorized_keys: a client
//                           is trusted because its exact certificate is
//                           pinned here, not because some CA signed it.
//
// Endpoints (all require a client certificate whose SHA-256 thumbprint is
// in authorized-clients.json; TLS is mutual -- see BuildServerCertificate /
// ValidateClientCertificate below):
//   GET  /v1/health                     -> { "status": "ok" }
//   POST /v1/exec   { "script": "...",  -> runs the given Python source
//                     "timeoutSeconds": -    through `python <tempfile>`
//                       30 }                 (argv, never a shell string)
//                                            and returns stdout/stderr/exit
//   POST /v1/upload (multipart/form-data,   -> saves each uploaded file
//                    one or more files)         under ./uploads and
//                                                returns the saved names
//
// Every request is written to tcs-audit.log (JSON lines) next to the
// executable: timestamp, client certificate thumbprint, endpoint, and for
// /v1/exec the full script text and result. Nothing is hidden from that
// log on purpose -- the point of an ops channel is that what happened
// through it is fully reconstructable afterwards.

using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

var (keyDir, port) = ParseArgs(args);

var serverCertificate = BuildServerCertificate(
    Path.Combine(keyDir, "server.crt"),
    Path.Combine(keyDir, "server.key"));

var authorizedThumbprints = LoadAuthorizedClients(
    Path.Combine(keyDir, "authorized-clients.json"));

var auditLogPath = Path.Combine(AppContext.BaseDirectory, "tcs-audit.log");
var auditLock = new object();

var uploadsDir = Path.Combine(AppContext.BaseDirectory, "uploads");
Directory.CreateDirectory(uploadsDir);

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    // Kestrel's default 30MB request body cap exists to protect a public
    // web server from casual abuse. That's the wrong default here: this is
    // a trusted, cert-pinned ops channel whose whole job is to move files
    // and run scripts, and the default silently aborts the TLS connection
    // (the client sees a raw EOF, not a clean error) on anything larger.
    // Uncapped matches the "no concurrency cap" design elsewhere -- the
    // upload endpoint streams straight to disk, so this trades disk space
    // for the cap, not memory.
    options.Limits.MaxRequestBodySize = null;

    // IPAddress.Any (0.0.0.0) is IPv4-only and would silently refuse every
    // IPv6 connection -- fe80::/10 link-local, fd00::/8 ULA, real IPv6 LAN
    // addresses, all of it -- which defeats the point of testing this
    // alongside ardcore's IPv6 path handling. ListenAnyIP binds a single
    // dual-stack socket on IPv6Any so both address families are accepted.
    options.ListenAnyIP(port, listenOptions =>
    {
        listenOptions.UseHttps(httpsOptions =>
        {
            httpsOptions.ServerCertificate = serverCertificate;
            httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            // The trust decision is entirely thumbprint pinning, so we
            // deliberately ignore the chain / SslPolicyErrors that a
            // self-signed client certificate would otherwise fail with.
            httpsOptions.ClientCertificateValidation = (certificate, _, _) =>
                authorizedThumbprints.Contains(Sha256Thumbprint(certificate));
        });
    });
});

// ReadFormAsync() enforces its own separate 128MB multipart-body limit
// independent of Kestrel's MaxRequestBodySize above -- both have to be
// raised, or a large upload just fails at 128MB instead of 30MB.
builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(o =>
{
    o.MultipartBodyLengthLimit = long.MaxValue;
});

var app = builder.Build();

app.MapGet("/v1/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/v1/exec", async (HttpContext context, ExecRequest request) =>
{
    if (string.IsNullOrEmpty(request.Script))
    {
        return Results.BadRequest(new { error = "script must be a non-empty string" });
    }

    var thumbprint = ClientThumbprint(context);
    var timeout = TimeSpan.FromSeconds(request.TimeoutSeconds is > 0 ? request.TimeoutSeconds.Value : 30);
    var started = Stopwatch.StartNew();

    var scriptPath = Path.Combine(Path.GetTempPath(), "tcs", $"{Guid.NewGuid():N}.py");
    Directory.CreateDirectory(Path.GetDirectoryName(scriptPath)!);
    await File.WriteAllTextAsync(scriptPath, request.Script, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

    ExecResult result;
    try
    {
        result = await RunPythonAsync(scriptPath, timeout);
    }
    finally
    {
        TryDelete(scriptPath);
    }

    started.Stop();
    WriteAudit(new
    {
        timestamp = DateTimeOffset.UtcNow,
        endpoint = "/v1/exec",
        clientThumbprint = thumbprint,
        script = request.Script,
        durationMs = started.ElapsedMilliseconds,
        result.ExitCode,
        result.TimedOut,
    });

    return Results.Ok(result);
});

app.MapPost("/v1/upload", async (HttpContext context) =>
{
    var thumbprint = ClientThumbprint(context);
    if (!context.Request.HasFormContentType)
    {
        return Results.BadRequest(new { error = "expected multipart/form-data" });
    }

    var form = await context.Request.ReadFormAsync();
    var saved = new List<string>();

    foreach (var file in form.Files)
    {
        // Strip any client-supplied directory components: only the file
        // name is trusted, and a fresh prefix avoids one upload silently
        // overwriting another (or an existing file) by name collision.
        var safeName = Path.GetFileName(file.FileName);
        if (string.IsNullOrWhiteSpace(safeName))
        {
            safeName = "upload.bin";
        }
        var storedName = $"{DateTimeOffset.UtcNow:yyyyMMddTHHmmssZ}_{Guid.NewGuid():N}_{safeName}";
        var destinationPath = Path.Combine(uploadsDir, storedName);

        await using (var destination = File.Create(destinationPath))
        {
            await file.CopyToAsync(destination);
        }

        saved.Add(storedName);
    }

    WriteAudit(new
    {
        timestamp = DateTimeOffset.UtcNow,
        endpoint = "/v1/upload",
        clientThumbprint = thumbprint,
        files = saved,
    });

    return Results.Ok(new { saved });
});

app.Run();

// ---- helpers ----------------------------------------------------------

static (string KeyDir, int Port) ParseArgs(string[] args)
{
    string? keyDir = null;
    int? port = null;

    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "-i" when i + 1 < args.Length:
                keyDir = args[++i];
                break;
            case "-p" when i + 1 < args.Length:
                port = int.Parse(args[++i]);
                break;
        }
    }

    if (keyDir is null)
    {
        throw new ArgumentException("missing required -i <keydir> argument");
    }
    if (!Directory.Exists(keyDir))
    {
        throw new DirectoryNotFoundException($"key directory not found: {keyDir}");
    }

    return (keyDir, port ?? 10122);
}

static X509Certificate2 BuildServerCertificate(string certPath, string keyPath)
{
    if (!File.Exists(certPath))
    {
        throw new FileNotFoundException("server certificate not found", certPath);
    }
    if (!File.Exists(keyPath))
    {
        throw new FileNotFoundException("server private key not found", keyPath);
    }

    return X509Certificate2.CreateFromPemFile(certPath, keyPath);
}

static HashSet<string> LoadAuthorizedClients(string path)
{
    if (!File.Exists(path))
    {
        throw new FileNotFoundException(
            "authorized-clients.json not found next to server.crt/server.key", path);
    }

    var json = File.ReadAllText(path);
    var thumbprints = JsonSerializer.Deserialize<string[]>(json)
        ?? throw new InvalidDataException("authorized-clients.json must be a JSON array of strings");

    return thumbprints
        .Select(NormalizeThumbprint)
        .ToHashSet(StringComparer.Ordinal);
}

static string Sha256Thumbprint(X509Certificate2 certificate) =>
    NormalizeThumbprint(Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)));

static string NormalizeThumbprint(string raw) =>
    raw.Replace(":", "").Replace(" ", "").Trim().ToUpperInvariant();

static string? ClientThumbprint(HttpContext context) =>
    context.Connection.ClientCertificate is { } cert ? Sha256Thumbprint(cert) : null;

static async Task<ExecResult> RunPythonAsync(string scriptPath, TimeSpan timeout)
{
    var pythonExe = Environment.GetEnvironmentVariable("TCS_PYTHON_EXE") is { Length: > 0 } configured
        ? configured
        : "python";

    var startInfo = new ProcessStartInfo
    {
        FileName = pythonExe,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    // Passed as an argv entry, never interpolated into a shell command
    // line: this is what sidesteps Windows/PowerShell quoting and
    // console-codepage encoding problems entirely.
    startInfo.ArgumentList.Add(scriptPath);

    using var process = new Process { StartInfo = startInfo };
    process.Start();

    var stdoutTask = process.StandardOutput.ReadToEndAsync();
    var stderrTask = process.StandardError.ReadToEndAsync();

    using var cts = new CancellationTokenSource(timeout);
    var timedOut = false;
    try
    {
        await process.WaitForExitAsync(cts.Token);
    }
    catch (OperationCanceledException)
    {
        timedOut = true;
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception exception)
        {
            // best effort: process may have exited between the timeout
            // firing and Kill() being called
            Console.Error.WriteLine($"tcs: failed to kill timed-out Python process: {exception}");
        }
    }

    var stdout = await stdoutTask;
    var stderr = await stderrTask;

    return new ExecResult(
        ExitCode: timedOut ? null : process.ExitCode,
        Stdout: stdout,
        Stderr: stderr,
        TimedOut: timedOut);
}

static void TryDelete(string path)
{
    try
    {
        File.Delete(path);
    }
    catch (Exception exception)
    {
        // best effort cleanup only
        Console.Error.WriteLine($"tcs: failed to delete temporary script '{path}': {exception}");
    }
}

void WriteAudit(object entry)
{
    var line = JsonSerializer.Serialize(entry);
    lock (auditLock)
    {
        File.AppendAllText(auditLogPath, line + Environment.NewLine);
    }
}

// ---- request/response shapes -------------------------------------------

record ExecRequest(string Script, int? TimeoutSeconds);

record ExecResult(int? ExitCode, string Stdout, string Stderr, bool TimedOut);
