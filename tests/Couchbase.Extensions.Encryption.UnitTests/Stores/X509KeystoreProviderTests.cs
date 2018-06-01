using System.Security.Cryptography.X509Certificates;
using Couchbase.Extensions.Encryption.Stores;
using Xunit;

namespace Couchbase.Extensions.Encryption.UnitTests.Stores
{
    public class X509KeystoreProviderTests
    {
        const string PublicKeyName = "MyPublicKeyName";
        const string PrivateKeyName = "MyPrivateKeyName";

        [Theory]
        [InlineData(PublicKeyName)]
        [InlineData(PrivateKeyName)]
        public void Test_GetKey(string keyname)
        {
            var keyStore = new X509CertificateKeyStore(new X509Certificate2("public_privatekey.pfx", "password",
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable))
            {
                PrivateKeyName = PrivateKeyName,
                PublicKeyName = PublicKeyName
            };

            var pkey = keyStore.GetKey(keyname);
            Assert.NotNull(pkey);
        }

        [Theory]
        [InlineData("BadPrivateKeyName")]
        [InlineData("BadPublicKeyName")]
        [InlineData(null)]
        [InlineData("")]
        public void Test_GetKey_Throws_CryptoKeyMismatchException_When_Keys_Not_Found(string keyname)
        {
            var keyStore = new X509CertificateKeyStore(new X509Certificate2("public_privatekey.pfx", "password",
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable))
            {
                PrivateKeyName = PrivateKeyName,
                PublicKeyName = PublicKeyName
            };

            Assert.Throws<CryptoKeyMisMatchException>(() => keyStore.GetKey(keyname));
        }
    }
}
