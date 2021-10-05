using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using Couchbase.Encryption.IntegrationTests;
using Couchbase.Encryption.Internal;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Couchbase.Encryption.UnitTests.Legacy
{
    public class LegacyRsaDecrypterTests
    {
        [Fact]
        public void Test_Upgrade_From_Rsa_To_AeadAes256CbcHmacSha512()
        {
            var keyring = new Keyring(new IKey[]
            {
                new Key("MyKeyName", GetKey("./Docs/rsa-private.xml")),
                new Key("upgrade-key", FakeKeyGenerator.GetKey(64))
            });

            var provider =
                new AeadAes256CbcHmacSha512Provider(
                    new AeadAes256CbcHmacSha512Cipher(), keyring);

            var cryptoManager = DefaultCryptoManager.Builder()
                .DefaultEncrypter(provider.Encrypter("upgrade-key"))
                .LegacyRsaDecrypter(keyring, "MyKeyName")
                .Build();

            var jsonObject = JObject.Parse(File.ReadAllText("./Docs/poco-rsa.json"));
            jsonObject.DecryptLegacyRsa<string>(cryptoManager, "__crypt_bar");
            jsonObject.DecryptLegacyRsa<int>(cryptoManager, "__crypt_foo");
            jsonObject.DecryptLegacyRsa<PocoMoco>(cryptoManager, "__crypt_childObject");
            jsonObject.DecryptLegacyRsa<List<int>>(cryptoManager, "__crypt_baz");
            jsonObject.DecryptLegacyRsa<string[]>(cryptoManager, "__crypt_faz");

            Assert.Equal("Bar", jsonObject.SelectToken("bar").Value<string>());
            Assert.Equal(90, jsonObject.SelectToken("foo").Value<int>());
            Assert.Equal( "Bar2", jsonObject.SelectToken("childObject.Bar").Value<string>());
            Assert.Equal(new List<int> { 3, 4 }, jsonObject.SelectToken("baz").Values<int>());
            Assert.Equal(new[] { "ted", "alice", "bill" }, jsonObject.SelectToken("faz").Values<string>());

            jsonObject.EncryptField(cryptoManager, "bar");
            jsonObject.EncryptField(cryptoManager, "foo");
            jsonObject.EncryptField(cryptoManager, "childObject");
            jsonObject.EncryptField(cryptoManager, "baz");
            jsonObject.EncryptField(cryptoManager, "faz");

            Assert.NotEqual("Bar", jsonObject.SelectToken("encrypted$bar.ciphertext").Value<string>());
            Assert.NotNull(jsonObject.SelectToken("encrypted$foo.ciphertext").Value<string>());
            Assert.NotEqual("Bar2", jsonObject.SelectToken("encrypted$bar.ciphertext").Value<string>());
            Assert.NotNull(jsonObject.SelectToken("encrypted$baz.ciphertext").Value<string>());
            Assert.NotNull(jsonObject.SelectToken("encrypted$faz.ciphertext").Value<string>());

        }

        private byte[] GetKey(string path)
        {
            var xd = new XmlDocument();
            xd.Load(path);
            return Encoding.UTF8.GetBytes(xd.InnerXml);
        }

        public class PocoMoco
        {
            public string Bar { get; set; }
        }
    }
}
