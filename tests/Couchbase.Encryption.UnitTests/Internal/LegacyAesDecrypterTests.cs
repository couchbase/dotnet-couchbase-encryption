using System;
using System.Text;
using Couchbase.Encryption.Attributes;
using Couchbase.Encryption.Internal;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Couchbase.Encryption.UnitTests.Internal
{
    public class LegacyAesDecrypterTests
    {
        public string legacyJson = "{" +
                                   "  \"__crypt_one\": {" +
                                   "    \"sig\": \"TkpyZnha4xd+FsX1aEGqB235d495oOUBfC4Y+Gbic4U=\"," +
                                   "    \"ciphertext\": \"MZI/xSiM7919UTM5CO/RWg==\"," +
                                   "    \"alg\": \"AES-128-HMAC-SHA256\"," +
                                   "    \"iv\": \"HIBdmnoQD4DUgkBj5LAMFw==\"," +
                                   "    \"kid\": \"aes128Key\"" +
                                   "  }," +
                                   "  \"__crypt_two\": {" +
                                   "    \"sig\": \"f0hWVdBM/pEcADl0eKx8Eq/KhP00/2oqXYXTJkt2xhA=\"," +
                                   "    \"ciphertext\": \"biERBQajaRxrfe8mXFqJag==\"," +
                                   "    \"alg\": \"AES-256-HMAC-SHA256\"," +
                                   "    \"iv\": \"03AUmzwQqnbs/JhkWGrIkw==\"," +
                                   "    \"kid\": \"aes256Key\"" +
                                   "  }" +
                                   "}";

        private static readonly Keyring KeyRing = new Keyring(new IKey[]
        {
            new Key("aes256Key", FakeKey(32)),
            new Key("hmacKey", FakeKey(7)),
            new Key("publickey", Encoding.UTF8.GetBytes("!mysecretkey#9^5usdk39d&dlf)03sL")),
            new Key("mysecret", Encoding.UTF8.GetBytes("myauthpassword")),
            new Key("upgrade-key", FakeKey(32) )
        });

        [Fact]
        public void Test_CanDecrypt()
        {
            var cryptoManager = DefaultCryptoManager.Builder()
                .LegacyAesDecrypters(KeyRing, "aes256Key", "hmacKey")
                .Build();

            var encrypted = (JObject)JObject.Parse(legacyJson).SelectToken("__crypt_two");
            var decrypted = encrypted.Decrypt("hmacKey", cryptoManager);

            Assert.Equal(2, Convert.ToInt32(Encoding.UTF8.GetString(decrypted)));
        }

        [Fact]
        public void Test_Upgrade()
        {
            var legacyJson =
                "{\"__crypt_bar\":{\"alg\":\"AES-256-CBC-HMAC-SHA256\",\"kid\":\"publickey\",\"ciphertext\":\"zOcxunCOdTSMxic4xz/F2w==\",\"sig\":\"7VYNnEBxuC8IvBu0egS3AM922NqWE6Mfy08KEghJ62Q=\",\"iv\":\"03AUmzwQqnbs/JhkWGrIkw==\"},\"foo\":2}";

            var provider = new AeadAes256CbcHmacSha512Provider(new AeadAes256CbcHmacSha512Cipher(new FakeRandomNumberGenerator(FakeKey(7))), KeyRing);
            var cryptoManager = DefaultCryptoManager.Builder()
                .LegacyAesDecrypters(KeyRing, "publickey", "secretkey")
                .DefaultEncrypter(provider.Encrypter("upgrade-key"))
                .Decrypter(provider.Decrypter())
                .Build();

            var serializerSettings = new JsonSerializerSettings
            {
                ContractResolver = new EncryptedFieldContractResolver(cryptoManager)
            };

            var decryptedPoco = JsonConvert.DeserializeObject<Poco>(legacyJson, serializerSettings);
            var encryptedJson = JsonConvert.SerializeObject(decryptedPoco, serializerSettings);
        }

        public class Poco
        {
            [EncryptedField(KeyName = "upgrade-key", LegacySigningKeyName = "secretkey")]
            public string bar { get; set; }
            public int Foo { get; set; }
        }

        private static byte[] FakeKey(int len)
        {
            var result = new byte[len];
            for (var i = 0; i < len; i++)
            {
                result[i] = (byte)i;
            }
            return result;
        }
    }
}
