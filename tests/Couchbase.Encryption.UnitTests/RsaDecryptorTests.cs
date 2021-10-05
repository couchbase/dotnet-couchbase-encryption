using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Couchbase.Encryption.Legacy;
using Xunit;

namespace Couchbase.Encryption.UnitTests
{
    public class RsaDecryptorTests
    {
        const string plainText = "The old grey goose jumped over the wrickety vase.";
        const string cipherText = "sl5PVX31v88DjgVpw4vr1FvULJ92/2EIdF9mkIG9zA70j5CNtqcr8eJWp4G3hgs1uqAlRPzeDbbxN2suNuIYB2wtoU/QpQKbB1XTVSQ8dHSJtL92mPt52bAiT44HpsS8wNJEXvSXQLJJx8ijkkqTc7pkM26WtoHh+SVwGwWClMk=";

        [Fact]
        public void DecryptTest()
        {
            var keyRing = new Keyring(new IKey[]
            {
                new Key("test-key", GetKey("./Docs/rsa-private.xml"))
            });
            var rsaDecrypter = new LegacyRsaDecrypter(keyRing, new LegacyRsaCipher());

            var encrypted = new EncryptionResult
            {
                Alg = "RSA-2048-OAEP-SHA1",
                Ciphertext = cipherText,
                Kid = "test-key"
            };

            var decryptedBytes = rsaDecrypter.Decrypt(encrypted);
            var actual = Encoding.UTF8.GetString(decryptedBytes);
            Assert.Equal(plainText, actual);
        }

        private byte[] GetKey(string path)
        {
            var xd = new XmlDocument();
            xd.Load(path);
            return Encoding.UTF8.GetBytes(xd.InnerXml);
        }
    }
}
