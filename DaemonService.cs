using System.Net;

namespace Tcs;

internal sealed class DaemonService(int port) : BackgroundService
{
    internal static async Task RunAsync(string name, int port)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows service mode requires Windows");
        var data = Deployment.Data;
        Directory.CreateDirectory(data);
        using var log = new StreamWriter(Path.Combine(data, "service.log"), append: true) { AutoFlush = true };
        var originalError = Console.Error;
        Console.SetError(TextWriter.Synchronized(log));
        try
        {
            var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
            {
                ContentRootPath = AppContext.BaseDirectory,
                Args = []
            });
            builder.Services.AddWindowsService(options => options.ServiceName = name);
            builder.Services.AddSingleton<IHostedService>(_ => new DaemonService(port));
            using var host = builder.Build();
            await host.RunAsync();
        }
        finally { Console.SetError(originalError); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            Console.Error.WriteLine($"{DateTimeOffset.UtcNow:O} Starting TCS on dual-stack TCP {port}");
            var daemon = new global::tcsd();
            await daemon.RunAsync(IPAddress.IPv6Any, port, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            Console.Error.WriteLine($"{DateTimeOffset.UtcNow:O} TCS service stopped");
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"{DateTimeOffset.UtcNow:O} TCS service failed: {exception}");
            Environment.Exit(1);
        }
    }
}
