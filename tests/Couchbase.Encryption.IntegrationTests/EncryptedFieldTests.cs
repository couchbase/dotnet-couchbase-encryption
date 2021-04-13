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

namespace Couchbase.Encryption.IntegrationTests
{
    public class EncryptedFieldTests
    {
       public static Task<DefaultCryptoManager> PreSetupCallAsync()
        {
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
            return Task.FromResult(cryptoManager);
        }

        public async Task<ICouchbaseCollection> getCollectionAsync()
        {
            var clusterOptions = new ConfigurationBuilder()
                .AddJsonFile("config.json")
                .Build()
                .GetSection("couchbase")
                .Get<ClusterOptions>();

            var cluster = await Cluster.ConnectAsync(clusterOptions);
            var bucket = await cluster.BucketAsync("default");
            var collection = bucket.DefaultCollection();

            return collection;
        }

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

        [Fact]
        public async Task Test_EncryptString()
        {
            var cryptoManager = PreSetupCallAsync();
            var encryptedTranscoder = new EncryptedFieldTranscoder((ICryptoManager)cryptoManager);
            var id = Guid.NewGuid().ToString();
            ICouchbaseCollection collection = (ICouchbaseCollection)getCollectionAsync(); ;
            var text = "plain text";
            try
            {
                await collection.InsertAsync(id, text, options =>
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

        [Fact]
        public async Task Test_EncryptInteger()
        {
            var cryptoManager = PreSetupCallAsync();
            var encryptedTranscoder = new EncryptedFieldTranscoder((ICryptoManager)cryptoManager);
            var id = Guid.NewGuid().ToString();
            ICouchbaseCollection collection = (ICouchbaseCollection)getCollectionAsync(); ;
            var number = 1234567;

            try
            {
                await collection.InsertAsync(id, number, options =>
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

        [Fact]
        public async Task Test_EncryptArrayList()
        {
            var cryptoManager = PreSetupCallAsync();
            var encryptedTranscoder = new EncryptedFieldTranscoder((ICryptoManager)cryptoManager);
            var id = Guid.NewGuid().ToString();
            ICouchbaseCollection collection = (ICouchbaseCollection)getCollectionAsync(); ;
            var arlist = new ArrayList()
                {
                    "KV", "Index", " ", true, "Eventing", null
                };

            try
            {
                await collection.InsertAsync(id, arlist, options =>
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

        [Fact]
        public async Task Test_EncryptArray()
        {
            var cryptoManager = PreSetupCallAsync();
            var encryptedTranscoder = new EncryptedFieldTranscoder((ICryptoManager)cryptoManager);
            var id = Guid.NewGuid().ToString();
            ICouchbaseCollection collection = (ICouchbaseCollection)getCollectionAsync(); ;
            string[] buckets = new string[3] { "Couchbase", "Membse", "Ephimeral" };

            try
            {
                await collection.InsertAsync(id, buckets, options =>
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

        [Fact]
        public async Task Test_EncryptObject()
        {
            var cryptoManager = PreSetupCallAsync();
            var encryptedTranscoder = new EncryptedFieldTranscoder((ICryptoManager)cryptoManager);
            var id = Guid.NewGuid().ToString();
            ICouchbaseCollection collection = (ICouchbaseCollection)getCollectionAsync(); ;
            Hashtable hashtable = new Hashtable();
            hashtable.Add(1, "Message1");
            hashtable.Add(2, "Message2");
            hashtable.Add(3, "Message3");

            try
            {
                await collection.InsertAsync(id, hashtable, options =>
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

        [Fact]
        public async Task Test_EncryptJSONObject()
        {
            var cryptoManager = PreSetupCallAsync();
            var encryptedTranscoder = new EncryptedFieldTranscoder((ICryptoManager)cryptoManager);
            var id = Guid.NewGuid().ToString();
            ICouchbaseCollection collection = (ICouchbaseCollection)getCollectionAsync(); ;
            string jsonData = @"{'userName':'john', 'password':'reallypassword$'}";

            var details = JObject.Parse(jsonData);

            try
            {
                await collection.InsertAsync(id, details, options =>
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

        [Fact]
        public async Task Test_EncryptNestedJSONObject()
        {
            var cryptoManager = PreSetupCallAsync();
            var encryptedTranscoder = new EncryptedFieldTranscoder((ICryptoManager)cryptoManager);
            var id = Guid.NewGuid().ToString();
            ICouchbaseCollection collection = (ICouchbaseCollection)getCollectionAsync(); ;
            string jsonStr = "{\n" +
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
