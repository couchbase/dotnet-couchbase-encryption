using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Couchbase.KeyValue;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Couchbase.Encryption.IntegrationTests.Fixtures;

public class SimpleFixture : IDisposable, IAsyncDisposable, IAsyncLifetime
{
    private ICluster _cluster;
    private IBucket _bucket;

    public async Task<ICouchbaseCollection> GetCollectionAsync()
    {
        return await _bucket.DefaultCollectionAsync();
    }

    public void Dispose()
    {
        _cluster?.Dispose();
    }

    public async Task InitializeAsync()
    {
        var clusterOptions = new ConfigurationBuilder()
            .AddJsonFile("config.json")
            .Build()
            .GetSection("couchbase")
            .Get<ClusterOptions>();

        IServiceCollection serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging(builder => builder
            .AddFilter(level => level >= LogLevel.Debug)
        );
        var loggerFactory = serviceCollection.BuildServiceProvider().GetService<ILoggerFactory>();
        loggerFactory.AddFile("Logs/myapp-{Date}.txt", LogLevel.Debug);
        clusterOptions.WithLogging(loggerFactory);

        Debug.Assert(clusterOptions != null,
            nameof(clusterOptions) + " != null");
        _cluster = await Cluster.ConnectAsync(clusterOptions);
        await _cluster.WaitUntilReadyAsync(TimeSpan.FromSeconds(5));

        _bucket = await _cluster.BucketAsync("default");
        await _bucket.WaitUntilReadyAsync(TimeSpan.FromSeconds(5));
    }

    async Task IAsyncLifetime.DisposeAsync()
    {
        await this.DisposeAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (_cluster != null)
        {
            await _cluster.DisposeAsync();
            _cluster = null;
        }
    }
}