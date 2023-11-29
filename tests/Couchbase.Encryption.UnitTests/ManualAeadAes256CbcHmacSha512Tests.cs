using System;
using Couchbase.Encryption.Internal;
using Couchbase.Encryption.UnitTests.Utils;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Couchbase.Encryption.UnitTests
{
    public class ManualAeadAes256CbcHmacSha512Tests
    {
        private static readonly byte[] KeyBytes = ("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" +
                                                   "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f" +
                                                   "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f" +
                                                   "30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f")
            .StringToByteArray();

        private static readonly byte[] Iv = "1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04".StringToByteArray();

        private static readonly Keyring KeyRing = new Keyring(new IKey[]
        {
            new Key("test-key", KeyBytes)
        });

        private ICryptoManager GetCryptoManager()
        {
            var provider =
                new AeadAes256CbcHmacSha512Provider(
                    new AeadAes256CbcHmacSha512Cipher(
                        new FakeRandomNumberGenerator(Iv)), KeyRing);

            return DefaultCryptoManager.Builder()
                .Decryptor(provider.Decryptor())
                .DefaultEncryptor(provider.Encryptor("test-key"))
                .Build();
        }

        [Fact]
        public void Test_Encrypt_String()
        {
            var cryptoManager = GetCryptoManager();

            var jsonObject = new JObject(new JProperty("string", "Frog and toad go the beach."));

            jsonObject.EncryptField(cryptoManager, "string");
            jsonObject.DecryptField<string>(cryptoManager, "string");

            var value = jsonObject.SelectToken("string").ToObject<string>();
            Assert.Equal("Frog and toad go the beach.", value);
        }

        [Fact]
        public void Test_Encrypt_Int()
        {
            var cryptoManager = GetCryptoManager();

            var jsonObject = new JObject(new JProperty("int", 10));

            jsonObject.EncryptField(cryptoManager, "int");
            jsonObject.DecryptField<int>(cryptoManager, "int");

            var value = jsonObject.SelectToken("int").Value<int>();
            Assert.Equal(10, value);
        }

        [Fact]
        public void Test_Encrypt_Array()
        {
            var cryptoManager = GetCryptoManager();

            var jsonObject = new JObject(new JProperty("array", new JArray(0, 1, 2, 3)));

            jsonObject.EncryptField(cryptoManager, "array");
            jsonObject.DecryptField<int>(cryptoManager, "array");

            var value = jsonObject.SelectToken("array").ToObject<int[]>();
            Assert.Equal(new[] {0, 1, 2, 3}, value);
        }

        [Fact]
        public void Test_Encrypt_Object()
        {
            var cryptoManager = GetCryptoManager();

            var jsonObject = new JObject(
                new JProperty("object",
                    new JObject(new JProperty("bar", "foo"))));

            jsonObject.EncryptField(cryptoManager, "object");
            jsonObject.DecryptField<int>(cryptoManager, "object");

            var value = jsonObject.SelectToken("object.bar").Value<string>();
            Assert.Equal("foo", value);
        }


        [Fact]
        public void Test_Encrypt_Float()
        {
            var cryptoManager = GetCryptoManager();

            var jsonObject = new JObject(new JProperty("float", 100.01f));
            jsonObject.EncryptField(cryptoManager, "float");
            jsonObject.DecryptField<int>(cryptoManager, "float");

            var value = jsonObject.SelectToken("float").Value<float>();
            Assert.Equal(100.01, Math.Round(value, 2));
        }

        [Fact]
        public void Test_Encrypt_Null()
        {
            var cryptoManager = GetCryptoManager();

            var jsonObject = new JObject(new JProperty("null", null));
            jsonObject.EncryptField(cryptoManager, "null");
            jsonObject.DecryptField<int>(cryptoManager, "null");

            var value = jsonObject.SelectToken("null");
            Assert.False(value.HasValues);
        }
    }
}
