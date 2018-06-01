using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Couchbase.Extensions.Encryption.Stores;
using Xunit;

namespace Couchbase.Extensions.Encryption.UnitTests.Stores
{
    public class X509KeystoreProviderTests
    {
        [Theory]
        [InlineData("PublicKey")]
        [InlineData("PrivateKey")]
        public void Test_GetKey(string keyname)
        {
            var keyStore = new X509KeyStore(new X509Certificate2("public_privatekey.pfx", "password",
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable));

            var pkey = keyStore.GetKey(keyname);
            Assert.NotNull(pkey);
        }
    }
}
