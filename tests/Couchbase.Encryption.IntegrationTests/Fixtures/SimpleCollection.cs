using Xunit;
using Xunit.Abstractions;

namespace Couchbase.Encryption.IntegrationTests.Fixtures;

[CollectionDefinition(Name)]
public class SimpleCollection : ICollectionFixture<SimpleFixture>
{
    public const string Name = "SimpleTestingCollection";

    // This class has no code, and is never created. Its purpose is simply
    // to be the place to apply [CollectionDefinition] and all the
    // ICollectionFixture<> interfaces.
}