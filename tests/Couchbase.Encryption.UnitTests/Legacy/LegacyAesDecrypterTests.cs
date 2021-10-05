using System.Text;
using Couchbase.Encryption.Attributes;
using Couchbase.Encryption.IntegrationTests;
using Couchbase.Encryption.Internal;
using Couchbase.Encryption.Legacy;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Couchbase.Encryption.UnitTests.Legacy
{
    public class LegacyAesDecrypterTests
    {
        [Fact]
        public void Test_Upgrade_With_Attributes()
        {
            // Arrange
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

            //We will need separate settings for deserialize and serialize so that the prefix is correctly applied
            var deserializerSettings = new JsonSerializerSettings
            {
                ContractResolver = new LegacyEncryptedFieldContractResolver(cryptoManager, "__crypt_")
            };

            var serializerSettings = new JsonSerializerSettings
            {
                ContractResolver = new EncryptedFieldContractResolver(cryptoManager)//uses the default "new" prefix for 2.0 "encrypted$"
            };

            // Act
            var decryptedPoco = JsonConvert.DeserializeObject<Poco>(legacyJson, deserializerSettings);
            var encryptedJson = JsonConvert.SerializeObject(decryptedPoco, serializerSettings);

            // Assert
            Assert.Equal("bar", decryptedPoco.Bar);
            Assert.Contains("upgrade-key", encryptedJson);
            Assert.Contains("AEAD_AES_256_CBC_HMAC_SHA512", encryptedJson);
            Assert.Contains("encrypted$", encryptedJson);
        }

        [Fact]
        public static void Test_Manual_Decryption_Rsa_To_AeadAes256CbcHmacSha512()
        {
            // Arrange
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

            var jsonObject = JObject.Parse(legacyJson);
            jsonObject.DecryptLegacyAes256<string>(cryptoManager, "hmacKey", "__crypt_bar");

            Assert.Equal("bar", jsonObject.SelectToken("bar").Value<string>());
            Assert.Equal(2, jsonObject.SelectToken("foo").Value<int>());

            jsonObject.EncryptField(cryptoManager, "bar");

            Assert.NotNull(jsonObject.SelectToken("encrypted$bar.ciphertext").Value<string>());
        }

        public class Poco
        {
            [EncryptedField(KeyName = "upgrade-key", LegacySigningKeyName = "hmacKey")]
            public string Bar { get; set; }
            public int Foo { get; set; }
        }
    }
}
