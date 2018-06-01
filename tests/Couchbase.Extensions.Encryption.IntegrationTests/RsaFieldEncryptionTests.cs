using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Serialization;
using Couchbase.Configuration.Client;
using Couchbase.Extensions.Encryption.Providers;
using Couchbase.Extensions.Encryption.Stores;
using Xunit;

namespace Couchbase.Extensions.Encryption.IntegrationTests
{
    public class RsaFieldEncryptionTests
    {
        const string PublicKeyName = "MyPublicKeyName";
        const string PrivateKeyName = "MyPrivateKeyName";

        [Fact]
        public void Test_Encrypt_String()
        {
            var key = "RSA-thepoco";
            var config = new ClientConfiguration(TestConfiguration.GetConfiguration());
            config.EnableFieldEncryption(new KeyValuePair<string, ICryptoProvider>("MyProvider",
                new RsaCryptoProvider(GetKeyStore())));

            using (var cluster = new Cluster(config))
            {
                cluster.Authenticate("Administrator", "password");
                var bucket = cluster.OpenBucket();
                var poco = new Poco
                {
                    Bar = "Bar",
                    Foo = 90,
                    ChildObject = new PocoMoco
                    {
                        Bar = "Bar2"
                    },
                    Fizz = "fizz",
                    Baz = new List<int> {3, 4}
                };

                var result = bucket.Upsert(key, poco);

                Assert.True(result.Success);

                var get = bucket.Get<Poco>(key);
                Assert.True(get.Success);
                Assert.Equal("Bar", get.Value.Bar);
                Assert.Equal(90, get.Value.Foo);
                Assert.Equal(new List<int> {3, 4}, get.Value.Baz);
                Assert.Equal("Bar2", get.Value.ChildObject.Bar);
            }
        }

        [Fact]
        public void Test_Encrypt2_String()
        {
            var key = "RSA-thepoco2_string";
            var config = new ClientConfiguration(TestConfiguration.GetConfiguration());
            config.EnableFieldEncryption(new KeyValuePair<string, ICryptoProvider>("MyProvider",
                new RsaCryptoProvider(GetKeyStore())));

            using (var cluster = new Cluster(config))
            {
                cluster.Authenticate("Administrator", "password");
                var bucket = cluster.OpenBucket();

                var poco = new Poco2
                {
                    Message = "The old grey goose jumped over the wrickety gate."
                };
                var result = bucket.Upsert(key, poco);

                Assert.True(result.Success);

                var get = bucket.Get<Poco2>(key);
                Assert.True(get.Success);
            }
        }

        [Fact]
        public void Test_Encrypt2_Int()
        {
            var key = "RSA-thepoco2_int";
            var config = new ClientConfiguration(TestConfiguration.GetConfiguration());
            config.EnableFieldEncryption(new KeyValuePair<string, ICryptoProvider>("MyProvider",
                new RsaCryptoProvider(GetKeyStore())));

            using (var cluster = new Cluster(config))
            {
                cluster.Authenticate("Administrator", "password");
                var bucket = cluster.OpenBucket();

                var poco = new PocoWithInt()
                {
                    Message = 10
                };
                var result = bucket.Upsert(key, poco);

                Assert.True(result.Success);

                var get = bucket.Get<Poco2>(key);
                Assert.True(get.Success);
            }
        }

        [Fact]
        public void Test_Encrypt2_IntString()
        {
            var key = "RSA-thepoco2_intstring";
            var config = new ClientConfiguration(TestConfiguration.GetConfiguration());
            config.EnableFieldEncryption(new KeyValuePair<string, ICryptoProvider>("MyProvider",
                new RsaCryptoProvider(GetKeyStore())));

            using (var cluster = new Cluster(config))
            {
                cluster.Authenticate("Administrator", "password");
                var bucket = cluster.OpenBucket();

                var poco = new PocoWithString()
                {
                    Message = "10"
                };
                var result = bucket.Upsert(key, poco);

                Assert.True(result.Success);

                var get = bucket.Get<Poco2>(key);
                Assert.True(get.Success);
            }
        }

        [Fact]
        public void Test_Encrypt_Array()
        {
            var key = "RSA-pocowitharray";
            var config = new ClientConfiguration(TestConfiguration.GetConfiguration());
            config.EnableFieldEncryption(new KeyValuePair<string, ICryptoProvider>("MyProvider",
                new RsaCryptoProvider(GetKeyStore())));

            using (var cluster = new Cluster(config))
            {
                cluster.Authenticate("Administrator", "password");
                var bucket = cluster.OpenBucket();

                var poco = new PocoWithArray()
                {
                    Message = new List<string>
                    {
                        "The",
                        "Old",
                        "Grey",
                        "Goose",
                        "Jumped",
                        "over",
                        "the",
                        "wrickety",
                        "gate"
                    }
                };
                var result = bucket.Upsert(key, poco);

                Assert.True(result.Success);

                var get = bucket.Get<PocoWithArray>(key);
                Assert.True(get.Success);
            }
        }


        [Fact]
        public void Test_Encrypt_NestedObject()
        {
            var key = "RSA-mypocokey";
            var config = new ClientConfiguration(TestConfiguration.GetConfiguration());
            config.EnableFieldEncryption(new KeyValuePair<string, ICryptoProvider>("MyProvider",
                new RsaCryptoProvider(GetKeyStore())));

            using (var cluster = new Cluster(config))
            {
                cluster.Authenticate("Administrator", "password");
                var bucket = cluster.OpenBucket();

                var poco = new PocoWithObject
                {
                    Message = new InnerObject
                    {
                        MyInt = 10,
                        MyValue = "The old grey goose jumped over the wrickety gate."
                    }
                };
                var result = bucket.Upsert(key, poco);

                var get = bucket.Get<PocoWithObject>(key);
                Assert.True(result.Success);
            }
        }

        public class PocoWithObject
        {
            [EncryptedField(Provider = "MyProvider")]
            public InnerObject Message { get; set; }
        }

        public class InnerObject
        {
            public string MyValue { get; set; }

            public int MyInt { get; set; }
        }

        public class PocoWithInt
        {
            [EncryptedField(Provider = "MyProvider")]
            public int Message { get; set; }
        }

        public class PocoWithString
        {
            [EncryptedField(Provider = "MyProvider")]
            public string Message { get; set; }
        }

        public class Poco2
        {
            [EncryptedField(Provider = "MyProvider")]
            public string Message { get; set; }
        }

        public class PocoWithArray
        {
            [EncryptedField(Provider = "MyProvider")]
            public List<string> Message { get; set; }
        }

        public class Poco
        {
            [EncryptedField(Provider = "MyProvider")]
            public string Bar { get; set; }

            [EncryptedField(Provider = "MyProvider")]
            public int Foo { get; set; }

            [EncryptedField(Provider = "MyProvider")]
            public List<int> Baz { get; set; }

            [EncryptedField(Provider = "MyProvider")]
            public PocoMoco ChildObject { get; set; }

            public string Fizz { get; set; }
        }

        public class PocoMoco
        {
            public string Bar { get; set; }
        }

        public IKeystoreProvider GetKeyStore()
        {
            X509Certificate2 cert = new X509Certificate2("public_privatekey.pfx", "password",
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

            return new X509KeyStore(cert);
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