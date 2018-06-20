using System;
using System.Collections.Generic;
using System.Security.Authentication;
using Couchbase.Extensions.Encryption.Providers;
using Couchbase.Extensions.Encryption.Stores;
using Newtonsoft.Json;
using Xunit;

namespace Couchbase.Extensions.Encryption.UnitTests
{
    public class EncryptableFieldConverterTests
    {
        [Fact]
        public void Test_Serialize()
        {
            var serializer = GetFieldSerializer();

            var poco = new Poco
            {
                StringField = "Woot!"
            };
            var bytes = serializer.Serialize(poco);
            var poco2 = serializer.Deserialize<Poco>(bytes, 0, bytes.Length);

            Assert.Equal(poco.StringField, poco2.StringField);
        }

        [Fact]
        public void When_Cipher_Is_Modified_HMAC_Throws_AuthException()
        {
            var serializer = GetFieldSerializer();

            var poco = new Poco
            {
                StringField = "Woot!"
            };

            var bytes = serializer.Serialize(poco);
            bytes[138] = Convert.FromBase64String(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("s")))[0];

            Assert.Throws<CryptoProviderSigningFailedException>(() => serializer.Deserialize<Poco>(bytes, 0, bytes.Length));
        }

        //[Fact]
        public void Fact_When_Provider_Not_Configured_CryptoProviderNotFoundException()
        {
            var providers = new Dictionary<string, ICryptoProvider>();
            var serializer = new EncryptedFieldSerializer(
                new JsonSerializerSettings { ContractResolver = new EncryptedFieldContractResolver(providers) },
                new JsonSerializerSettings { ContractResolver = new EncryptedFieldContractResolver(providers) });

            Assert.Throws<CryptoProviderNotFoundException>(() => serializer.Serialize(new Poco
            {
                StringField = "Woot!"
            }));
        }

        public class Poco
        {
            [EncryptedField(Provider = "MyProvider")]
            public string StringField { get; set; }
        }

        public EncryptedFieldSerializer GetFieldSerializer()
        {
            var providers = new Dictionary<string, ICryptoProvider>
            {
                {"MyProvider", new AesCryptoProvider(new InsecureKeyStore(
                    new KeyValuePair<string, string>("publickey", "!mysecretkey#9^5usdk39d&dlf)03sL"),
                    new KeyValuePair<string, string>("myauthsecret", "mysecret")))
                {
                    PublicKeyName = "publickey",
                    SigningKeyName = "myauthsecret"
                }}
            };
            return new EncryptedFieldSerializer(
                new JsonSerializerSettings { ContractResolver = new EncryptedFieldContractResolver(providers) },
                new JsonSerializerSettings { ContractResolver = new EncryptedFieldContractResolver(providers) });
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
