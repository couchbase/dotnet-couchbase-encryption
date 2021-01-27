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

namespace Couchbase.Encryption.IntegrationTests
{
    public class EncryptedFieldTests
    {
        [Fact]
        public async Task Test_Upgrade()
        {
            var clusterOptions = new ConfigurationBuilder()
                .AddJsonFile("config.json")
                .Build()
                .GetSection("couchbase")
                .Get<ClusterOptions>();

            var cluster = await Cluster.ConnectAsync(clusterOptions);
            var bucket = await cluster.BucketAsync("default");
            var collection = bucket.DefaultCollection();

            var keyring = new Keyring(new IKey[]
            {
                new Key("publickey", Encoding.UTF8.GetBytes("!mysecretkey#9^5usdk39d&dlf)03sL")),
                new Key("hmacKey", Encoding.UTF8.GetBytes("mysecret")),
                new Key("upgrade-key", FakeKeyGenerator.GetKey(64))
            });

            var legacyJson =
                "{\"__crypt_bar\":{\"alg\":\"AES-256-CBC-HMAC-SHA256\",\"kid\":\"publickey\",\"ciphertext\":\"zOcxunCOdTSMxic4xz/F2w==\",\"sig\":\"7VYNnEBxuC8IvBu0egS3AM922NqWE6Mfy08KEghJ62Q=\",\"iv\":\"03AUmzwQqnbs/JhkWGrIkw==\"},\"foo\":2}";

            var provider = new AeadAes256CbcHmacSha512Provider(new AeadAes256CbcHmacSha512Cipher(), keyring);
            var cryptoManager = DefaultCryptoManager.Builder()
                .LegacyAesDecrypters(keyring, "hmacKey")
                .DefaultEncrypter(provider.Encrypter("upgrade-key"))
                .Decrypter(provider.Decrypter())
                .Build();

            var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);

            var jsonObj = JsonConvert.DeserializeObject<JObject>(legacyJson);
            var id = Guid.NewGuid().ToString();

            try
            {
                await collection.InsertAsync(id, jsonObj, options => options.Expiry(TimeSpan.FromSeconds(10)))
                    .ConfigureAwait(false);

                var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder))
                    .ConfigureAwait(false);

                var val = result.ContentAs<EncryptedFieldTests.UpgradePoco>();
                Assert.NotNull(val);
            }
            finally
            {
                await collection.RemoveAsync(id).ConfigureAwait(false);
            }

        }

        [Fact]
        public async Task Test_RoundTrip()
        {
            var clusterOptions = new ConfigurationBuilder()
                .AddJsonFile("config.json")
                .Build()
                .GetSection("couchbase")
                .Get<ClusterOptions>();

            var cluster = await Cluster.ConnectAsync(clusterOptions);
            var bucket = await cluster.BucketAsync("default");
            var collection = bucket.DefaultCollection();

            var id = Guid.NewGuid().ToString();

            var provider =
                new AeadAes256CbcHmacSha512Provider(
                    new AeadAes256CbcHmacSha512Cipher(), new Keyring(new IKey[]
                    {
                       new Key("test-key", FakeKeyGenerator.GetKey(64))
                    }));

            var cryptoManager = DefaultCryptoManager.Builder()
                .Decrypter(provider.Decrypter())
                .DefaultEncrypter(provider.Encrypter("test-key"))
                .Build();

            var encryptedTranscoder = new EncryptedFieldTranscoder(cryptoManager);

            var pocono = new EncryptedFieldTests.Poco
            {
                Bar = "bar",
                Foo = 2
            };

            try
            {
                await collection.InsertAsync(id, pocono, options =>
                    {
                        options.Transcoder(encryptedTranscoder);
                        options.Expiry(TimeSpan.FromSeconds(10));
                    })
                    .ConfigureAwait(false);

                var result = await collection.GetAsync(id, options => options.Transcoder(encryptedTranscoder))
                    .ConfigureAwait(false);

                var val = result.ContentAs<EncryptedFieldTests.Poco>();
                Assert.NotNull(val);
            }
            finally
            {
                await collection.RemoveAsync(id).ConfigureAwait(false);
            }
        }

        public class UpgradePoco
        {
            [EncryptedField(KeyName = "upgrade-key", LegacySigningKeyName = "hmacKey")]
            public string Bar { get; set; }
            public int Foo { get; set; }
        }

        public class Poco
        {
            [EncryptedField(KeyName = "test-key")]
            public string Bar { get; set; }
            public int Foo { get; set; }
        }
    }
}
