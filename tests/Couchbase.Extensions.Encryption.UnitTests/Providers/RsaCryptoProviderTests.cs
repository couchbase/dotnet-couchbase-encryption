using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Serialization;
using Couchbase.Extensions.Encryption.Providers;
using Couchbase.Extensions.Encryption.Stores;
using Xunit;

namespace Couchbase.Extensions.Encryption.UnitTests.Providers
{
    public class RsaCryptoProviderTests
    {
        private IKeystoreProvider _keystore;

        public RsaCryptoProviderTests()
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                var privateKey = rsa.ExportParameters(true);
                var publicKey = rsa.ExportParameters(false);

                _keystore = new InsecureKeyStore(
                    new KeyValuePair<string, string>("PrivateKey", GetKeyAsString(privateKey)),
                    new KeyValuePair<string, string>("PublicKey", GetKeyAsString(publicKey)));
            }
        }

        [Fact]
        public void Test_Encrypt()
        {
            var rsaCryptoProvider = new RsaCryptoProvider
            {
                KeyStore = _keystore
            };

            var someText = "The old grey goose jumped over the wrickety vase.";

            var encryptedTest = rsaCryptoProvider.Encrypt(someText);
            Assert.NotEqual(encryptedTest, someText);
        }

        [Fact]
        public void Test_Decrypt()
        {
            var rsaCryptoProvider = new RsaCryptoProvider
            {
                KeyStore =_keystore
            };

            var someText = "The old grey goose jumped over the wrickety vase.";

            var encryptedTest = rsaCryptoProvider.Encrypt(someText);
            Assert.NotEqual(encryptedTest, someText);

            var decryptedText = rsaCryptoProvider.Decrypt(encryptedTest);
            Assert.Equal(decryptedText, someText);
        }

        private string GetKeyAsString(RSAParameters parameters)
        {
            using (var writer = new StringWriter())
            {
                var serializer = new XmlSerializer(typeof(RSAParameters));
                serializer.Serialize(writer, parameters);

                return writer.ToString();
            }
        }
    }
}

#region [License information]
/* ************************************************************

 *    Copyright (c) 2018 Couchbase, Inc.
 *
 *    Use of this software is subject to the Couchbase Inc.
 *    Enterprise Subscription License Agreement which may be found
 *    at https://www.couchbase.com/ESLA-11132015.

 * ************************************************************/
#endregion
