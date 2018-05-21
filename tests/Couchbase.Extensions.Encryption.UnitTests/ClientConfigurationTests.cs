using Couchbase.Configuration.Client;
using Couchbase.Extensions.Encryption.Providers;
using Couchbase.Extensions.Encryption.Stores;
using Xunit;

namespace Couchbase.Extensions.Encryption.UnitTests
{
    public class ClientConfigurationTests
    {
        [Fact]
        public void Test_EnableFieldEncryption()
        {
            var config = new ClientConfiguration();
            config.EnableFieldEncryption("MyProvider", new AesCryptoProvider(new InsecureKeyStore("thekeyname", "thekey")));

            Assert.IsType<EncryptedFieldSerializer>(config.Serializer());
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
