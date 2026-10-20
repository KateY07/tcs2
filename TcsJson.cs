using System.Text.Json.Serialization;

public sealed record ClientExecRequest(
    [property: JsonPropertyName("script")] string Script,
    [property: JsonPropertyName("timeoutSeconds")] int TimeoutSeconds,
    [property: JsonPropertyName("maxOutput")] int? MaxOutput = null);

public sealed record ExecRequest(
    [property: JsonPropertyName("script")] string Script,
    [property: JsonPropertyName("timeoutSeconds")] int? TimeoutSeconds,
    [property: JsonPropertyName("maxOutput")] int? MaxOutput = null);

// StdoutOmitted/StderrOmitted: characters dropped by the per-stream output cap (0 = nothing dropped).
// DurationMs: server-side wall time of the Python process (start to exit or kill).
public sealed record ExecResult(int? ExitCode, string Stdout, string Stderr, bool TimedOut,
    long StdoutOmitted = 0, long StderrOmitted = 0, long DurationMs = 0);

public sealed record UploadResponse([property: JsonPropertyName("saved")] string[] Saved);

public sealed record TcsExecAudit(
    [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
    [property: JsonPropertyName("endpoint")] string Endpoint,
    [property: JsonPropertyName("clientFingerprint")] string ClientFingerprint,
    [property: JsonPropertyName("durationMs")] long DurationMs,
    [property: JsonPropertyName("exitCode")] int? ExitCode,
    [property: JsonPropertyName("timedOut")] bool TimedOut);

public sealed record TcsUploadAudit(
    [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
    [property: JsonPropertyName("endpoint")] string Endpoint,
    [property: JsonPropertyName("clientFingerprint")] string ClientFingerprint,
    [property: JsonPropertyName("files")] string[] Files);

public sealed record LegacyExecAudit(
    [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
    [property: JsonPropertyName("endpoint")] string Endpoint,
    [property: JsonPropertyName("clientThumbprint")] string? ClientThumbprint,
    [property: JsonPropertyName("script")] string Script,
    [property: JsonPropertyName("durationMs")] long DurationMs,
    [property: JsonPropertyName("exitCode")] int? ExitCode,
    [property: JsonPropertyName("timedOut")] bool TimedOut);

public sealed record LegacyUploadAudit(
    [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
    [property: JsonPropertyName("endpoint")] string Endpoint,
    [property: JsonPropertyName("clientThumbprint")] string? ClientThumbprint,
    [property: JsonPropertyName("files")] string[] Files);

[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(ClientExecRequest))]
[JsonSerializable(typeof(ExecRequest))]
[JsonSerializable(typeof(ExecResult))]
[JsonSerializable(typeof(UploadResponse))]
[JsonSerializable(typeof(TcsExecAudit))]
[JsonSerializable(typeof(TcsUploadAudit))]
[JsonSerializable(typeof(LegacyExecAudit))]
[JsonSerializable(typeof(LegacyUploadAudit))]
internal partial class TcsJsonContext : JsonSerializerContext;
