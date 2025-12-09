#nullable enable
using System;
using System.Text;
using System.Threading.Tasks;
using Couchbase.Encryption.Attributes;
using Couchbase.Encryption.Internal;
using Microsoft.Extensions.Configuration;
using Couchbase.KeyValue;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;
using System.Collections;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;
using Couchbase.Encryption.IntegrationTests.Fixtures;
using Xunit.Abstractions;

namespace Couchbase.Encryption.IntegrationTests;

[Collection(SimpleCollection.Name)]
public class EncryptedFieldTests
{
    private readonly SimpleFixture _fixture;
    private readonly ITestOutputHelper _outputHelper;

    public EncryptedFieldTests(SimpleFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _outputHelper = outputHelper;
    }

    public static ICryptoManager PreSetupCall()
    {
        var provider =
            new AeadAes256CbcHmacSha512Provider(
                new AeadAes256CbcHmacSha512Cipher(), new Keyring(new IKey[]
                {
                    new Key("test-key", FakeKeyGenerator.GetKey(64))
                }));

        var cryptoManager = DefaultCryptoManager.Builder()
            .Decryptor(provider.Decryptor())
            .DefaultEncryptor(provider.Encryptor("test-key"))
            .Build();
        return cryptoManager;
    }

    private async Task<ICouchbaseCollection> GetCollectionAsync()
    {
        return await _fixture.GetCollectionAsync();
    }

    [Fact]
    public async Task Test_Upgrade()
    {
        var collection = await _fixture.GetCollectionAsync();

        var keyring = new Keyring([
            new Key("publickey", Encoding.UTF8.GetBytes("!mysecretkey#9^5usdk39d&dlf)03sL")),
            new Key("hmacKey", Encoding.UTF8.GetBytes("mysecret")),
            new Key("upgrade-key", FakeKeyGenerator.GetKey(64))
        ]);

        var legacyJson =
            "{\"__crypt_bar\":{\"alg\":\"AES-256-CBC-HMAC-SHA256\",\"kid\":\"publickey\",\"ciphertext\":\"zOcxunCOdTSMxic4xz/F2w==\",\"sig\":\"7VYNnEBxuC8IvBu0egS3AM922NqWE6Mfy08KEghJ62Q=\",\"iv\":\"03AUmzwQqnbs/JhkWGrIkw==\"},\"foo\":2}";

        var provider = new AeadAes256CbcHmacSha512Provider(new AeadAes256CbcHmacSha512Cipher(), keyring);
        var cryptoManager = DefaultCryptoManager.Builder()
            .LegacyAesDecryptors(keyring, "hmacKey")
            .DefaultEncryptor(provider.Encryptor("upgrade-key"))
            .Decryptor(provider.Decryptor())
            .Build();

        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);

        var jsonObj = JsonConvert.DeserializeObject<JObject>(legacyJson);
        var id = Guid.NewGuid().ToString();

        try
        {
            await collection.InsertAsync(id, jsonObj, options => options.Expiry(TimeSpan.FromSeconds(10000)));

            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder));

            var val = result.ContentAs<UpgradePoco>();
            Assert.NotNull(val);
        }
        finally
        {
            await collection.RemoveAsync(id);
        }

    }

    [Fact]
    public async Task Test_ExampleAsync()
    {
        var provider =
            new AeadAes256CbcHmacSha512Provider(
                new AeadAes256CbcHmacSha512Cipher(), new Keyring(new IKey[]
                {
                    new Key("test-key", FakeKeyGenerator.GetKey(64))
                }));

        var cryptoManager = DefaultCryptoManager.Builder()
            .Decryptor(provider.Decryptor())
            .Encryptor("test-key", provider.Encryptor("test-key"))
            .Build();

        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);

        var clusterOptions = new ConfigurationBuilder()
            .AddJsonFile("config.json")
            .Build()
            .GetSection("couchbase")
            .Get<ClusterOptions>();

        Debug.Assert(clusterOptions != null, nameof(clusterOptions) + " != null");
        clusterOptions.WithTranscoder(encryptedTranscoder);

        var collection = await _fixture.GetCollectionAsync();

        var id = Guid.NewGuid().ToString();

        var poco = new Poco
        {
            Bar = "bar",
            Foo = 23
        };

        try
        {
            await collection.InsertAsync(id, poco, options =>
            {
                options.Transcoder(encryptedTranscoder);
                options.Expiry(TimeSpan.FromSeconds(1000));
            });

            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder));

            var val = result.ContentAs<Poco>();
            Assert.Equal(poco, val);
        }
        catch(Exception e)
        {
            _outputHelper.WriteLine(e.Message);
        }
        finally
        {
            await collection.RemoveAsync(id);
        }
    }

    [Fact]
    public async Task Test_RoundTrip()
    {
        var collection = await _fixture.GetCollectionAsync();
        var id = Guid.NewGuid().ToString();

        var provider =
            new AeadAes256CbcHmacSha512Provider(
                new AeadAes256CbcHmacSha512Cipher(), new Keyring(new IKey[]
                {
                    new Key("test-key", FakeKeyGenerator.GetKey(64))
                }));

        var cryptoManager = DefaultCryptoManager.Builder()
            .Decryptor(provider.Decryptor())
            .Encryptor("test-key", provider.Encryptor("test-key"))
            .Build();

        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);

        var poco = new Poco
        {
            Bar = "bar",
            Foo = 2
        };

        try
        {
            await collection.InsertAsync(id, poco, options =>
            {
                options.Transcoder(encryptedTranscoder);
                options.Expiry(TimeSpan.FromSeconds(10));
            });

            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder));

            var val = result.ContentAs<Poco>();
            Assert.NotNull(val);
        }
        catch(Exception e)
        {
            _outputHelper.WriteLine(e.Message);
        }
        finally
        {
            await collection.RemoveAsync(id);
        }
    }

    [Fact]
    public async Task Test_RoundTrip_Multiple_Custom_Encryption_Keys()
    {
        var collection = await _fixture.GetCollectionAsync();
        var id = "KeyTest_" + Guid.NewGuid().ToString()[..6];

        var encryptionKeys = new List<IKey>
        {
            new Key("myKey1", FakeKeyGenerator.GetKey(64)),
            new Key("myKey2", FakeKeyGenerator.GetKey(64)),
            new Key("myKey3", FakeKeyGenerator.GetKey(64))
        };

        var provider =
            new AeadAes256CbcHmacSha512Provider(
                new AeadAes256CbcHmacSha512Cipher(), new Keyring(encryptionKeys));

        var cryptoManagerBuilder = DefaultCryptoManager.Builder()
            .Decryptor(provider.Decryptor());

        encryptionKeys.ForEach(key => cryptoManagerBuilder.Encryptor(key.Id, provider.Encryptor(key.Id)));

        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManagerBuilder.Build());

        var poco = new PocoMultipleKeys
        {
            Field1 = "field1",
            Field2 = "field2",
            Field3 = "field3"
        };

        await collection.InsertAsync(id, poco, options =>
        {
            options.Transcoder(encryptedTranscoder);
            options.Timeout(TimeSpan.FromMinutes(1));
        });

        try
        {
            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder));
            var val = result.ContentAs<PocoMultipleKeys>();
            Assert.True(poco.Equals(val));
        }
        finally
        {
            await collection.RemoveAsync(id);
        }
    }

    [Fact]
    public async Task Test_EncryptString()
    {
        var cryptoManager = PreSetupCall();
        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);
        var id = Guid.NewGuid().ToString();
        var collection = await GetCollectionAsync();
        var text = "plain text";
        try
        {
            await collection.InsertAsync(id, text, options =>
            {
                options.Transcoder(encryptedTranscoder);
                options.Expiry(TimeSpan.FromSeconds(10));
            });

            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder));

            var val = result.ContentAs<string>();
            Assert.NotNull(val);
        }
        finally
        {
            await collection.RemoveAsync(id);
        }
    }

    [Fact]
    public async Task Test_EncryptInteger()
    {
        var cryptoManager = PreSetupCall();
        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);
        var id = Guid.NewGuid().ToString();
        var collection = await GetCollectionAsync();
        var number = 1234567;

        try
        {
            await collection.InsertAsync(id, number, options =>
            {
                options.Transcoder(encryptedTranscoder);
                options.Expiry(TimeSpan.FromSeconds(10));
            });

            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder));

            var val = result.ContentAs<int>();
            Assert.Equal(number, val);
        }
        finally
        {
            await collection.RemoveAsync(id);
        }
    }

    [Fact]
    public async Task Test_EncryptArrayList()
    {
        var cryptoManager = PreSetupCall();
        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);
        var id = Guid.NewGuid().ToString();
        var collection = await GetCollectionAsync();
        var arlist = new ArrayList
        {
            "KV", "Index", " ", true, "Eventing", null
        };

        try
        {
            await collection.InsertAsync(id, arlist, options =>
            {
                options.Transcoder(encryptedTranscoder);
                options.Expiry(TimeSpan.FromSeconds(10));
            });

            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder));

            var val = result.ContentAs<ArrayList>();
            Assert.NotNull(val);
        }
        finally
        {
            await collection.RemoveAsync(id);
        }
    }

    [Fact]
    public async Task Test_EncryptArray()
    {
        var cryptoManager = PreSetupCall();
        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);
        var id = Guid.NewGuid().ToString();
        var collection = await GetCollectionAsync();
        var buckets = new[] { "Couchbase", "Membase", "Ephemeral" };

        try
        {
            await collection.InsertAsync(id, buckets, options =>
            {
                options.Transcoder(encryptedTranscoder);
                options.Expiry(TimeSpan.FromSeconds(10));
            });

            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder));

            var val = result.ContentAs<string[]>();
            Assert.NotNull(val);
        }
        finally
        {
            await collection.RemoveAsync(id);
        }
    }

    [Fact]
    public async Task Test_EncryptObject()
    {
        var cryptoManager = PreSetupCall();
        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);
        var id = Guid.NewGuid().ToString();
        var collection = await GetCollectionAsync();
        var hashtable = new Hashtable {{1, "Message1"}, {2, "Message2"}, {3, "Message3"}};

        try
        {
            await collection.InsertAsync(id, hashtable, options =>
                {
                    options.Transcoder(encryptedTranscoder);
                    options.Expiry(TimeSpan.FromSeconds(10));
                })
                ;

            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder));

            var val = result.ContentAs<Poco>();
            Assert.NotNull(val);
        }
        finally
        {
            await collection.RemoveAsync(id);
        }
    }

    [Fact]
    public async Task Test_EncryptJSONObject()
    {
        var cryptoManager = PreSetupCall();
        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);
        var id = Guid.NewGuid().ToString();
        var collection = await GetCollectionAsync();
        var jsonData = @"{'userName':'john', 'password':'reallypassword$'}";

        var details = JObject.Parse(jsonData);

        try
        {
            await collection.InsertAsync(id, details, options =>
            {
                options.Transcoder(encryptedTranscoder);
                options.Expiry(TimeSpan.FromSeconds(10));
            }) ;

            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder));

            var val = result.ContentAs<Poco>();
            Assert.NotNull(val);
        }
        finally
        {
            await collection.RemoveAsync(id);
        }
    }

    [Fact]
    public async Task Test_EncryptNestedJSONObject()
    {
        var cryptoManager = PreSetupCall();
        var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);
        var id = Guid.NewGuid().ToString();
        var collection = await GetCollectionAsync();
        var jsonStr = "{\n" +
                      "  \"userinfo\": [\n" +
                      "    {\n" +
                      "      \"firstName\": \"John\",\n" +
                      "      \"lastName\": \"Doe\",\n" +
                      "      \"username\": \"jdoe\"\n" +
                      "    },\n" +
                      "    {\n" +
                      "      \"firstName\": \"Alex\",\n" +
                      "      \"lastName\": \"Daniel\",\n" +
                      "      \"username\": \"adaniel\"\n" +
                      "    }\n" +
                      "  ],\n" +
                      "  \"login\": [\n" +
                      "    {\n" +
                      "      \"username\": \"ajoe\",\n" +
                      "      \"status\": \"loggedin\"\n" +
                      "    }\n" +
                      "  ]\n" +
                      "}";

        var details = JObject.Parse(jsonStr);

        try
        {
            await collection.InsertAsync(id, details, options =>
            {
                options.Transcoder(encryptedTranscoder);
                options.Expiry(TimeSpan.FromSeconds(1000));
            });

            var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder)) ;

            var val = result.ContentAs<Poco>();
            Assert.NotNull(val);
        }
        finally
        {
            await collection.RemoveAsync(id);
        }
    }

    public class UpgradePoco
    {
        [EncryptedField(KeyName = "upgrade-key", LegacySigningKeyName = "hmacKey")]
        public string? Bar { get; set; }
        public int Foo { get; set; }
    }

    public class Poco : IEquatable<Poco>
    {
        [EncryptedField(KeyName = "test-key")]
        public required string Bar { get; init; }
        public int Foo { get; init; }

        public override bool Equals(object? obj)
        {
            return obj is Poco that && that.Bar == this.Bar && that.Foo == this.Foo;
        }

        public bool Equals(Poco? other)
        {
            if (other is null) return false;
            if (ReferenceEquals(this, other)) return true;
            return Bar == other.Bar && Foo == other.Foo;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Bar, Foo);
        }

        public static bool operator ==(Poco? left, Poco? right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(Poco? left, Poco? right)
        {
            return !Equals(left, right);
        }
    }

    public class PocoMultipleKeys : IEquatable<PocoMultipleKeys>
    {
        [EncryptedField(KeyName = "myKey1")]
        public string? Field1 { get; init; }

        [EncryptedField(KeyName = "myKey2")]
        public string? Field2 { get; init; }

        [EncryptedField(KeyName = "myKey3")]
        public string? Field3 { get; init; }

        public override bool Equals(object? obj)
        {
            return obj is PocoMultipleKeys that && that.Field1 == this.Field1 && that.Field2 == this.Field2 && that.Field3 == this.Field3;
        }

        public bool Equals(PocoMultipleKeys? other)
        {
            if (other is null) return false;
            if (ReferenceEquals(this, other)) return true;
            return Field1 == other.Field1 && Field2 == other.Field2 && Field3 == other.Field3;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Field1, Field2, Field3);
        }

        public static bool operator ==(PocoMultipleKeys? left, PocoMultipleKeys? right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(PocoMultipleKeys? left, PocoMultipleKeys? right)
        {
            return !Equals(left, right);
        }
    }
}