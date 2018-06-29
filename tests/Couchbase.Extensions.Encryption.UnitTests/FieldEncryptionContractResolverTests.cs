using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Couchbase.Extensions.Encryption.Providers;
using Couchbase.Extensions.Encryption.Stores;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Xunit;
using Xunit.Abstractions;

namespace Couchbase.Extensions.Encryption.UnitTests
{
    public class FieldEncryptionContractResolverTests
    {
        private readonly ITestOutputHelper output;

        public FieldEncryptionContractResolverTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Fact]
        public void When_No_CryptoProviders_Configured_Throw_ArgumentOutOfRangeException()
        {
            var cryptoProviders = new Dictionary<string, ICryptoProvider>
            {
                //uh oh
            };

            Assert.Throws<ArgumentOutOfRangeException>(() => new EncryptedFieldContractResolver(cryptoProviders));
        }

        [Fact]
        public void When_CryptoProviders_Is_Null_Throw_ArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new EncryptedFieldContractResolver(null));
        }

        [Fact]
        public void When_Alias_Does_Not_Match_Configured_CryptoProvider_Throw_CryptoProviderNotFoundException()
        {
            var cryptoProviders = new Dictionary<string, ICryptoProvider>
            {
                {
                    "IDONTMATCH!", new AesCryptoProvider(new InsecureKeyStore(
                        new KeyValuePair<string, string>("publickey", "!mysecretkey#9^5usdk39d&dlf)03sL"),
                        new KeyValuePair<string, string>("myauthsecret", "mysecret")))
                    {
                        PublicKeyName = "publickey",
                        SigningKeyName = "myauthsecret"
                    }
                }
            };
            ITraceWriter traceWriter = new MemoryTraceWriter();

            var settings = new JsonSerializerSettings
            {
                ContractResolver = new EncryptedFieldContractResolver(cryptoProviders),
                TraceWriter = traceWriter
            };

            var pocoPlain = new Poco3 {Foo = 2, Bar="bar"};

            Assert.Throws<CryptoProviderNotFoundException>(() => JsonConvert.SerializeObject(pocoPlain, settings));
        }

        [Fact]
        public void Test_String_Encryption_RoundTrip()
        {
            var settings = GetSettings();
            var pocoPlain = new Poco {Bar = "bar", Foo = 2};

            var json = JsonConvert.SerializeObject(pocoPlain, settings);

            Assert.Contains("__crypt", json); ;

            var poco = JsonConvert.DeserializeObject<Poco>(json, settings);
            Assert.Equal("bar", poco.Bar);
        }

        [Fact]
        public void Test_Integer_Encryption_RoundTrip()
        {
            var settings = GetSettings();
            var pocoPlain = new Poco1 {Foo = 2};

            var json = JsonConvert.SerializeObject(pocoPlain, settings);

            Assert.Contains("__crypt", json); ;

            var poco = JsonConvert.DeserializeObject<Poco1>(json, settings);
            Assert.Equal(2, poco.Foo);
        }

        [Fact]
        public void Test_List_Encryption_RoundTrip()
        {
            var settings = GetSettings();
            var pocoPlain = new Poco2 { Foo = new List<int> {3, 4, 5} };

            var json = JsonConvert.SerializeObject(pocoPlain, settings);

            var poco = JsonConvert.DeserializeObject<Poco2>(json, settings);
            Assert.Equal(new List<int> { 3, 4, 5 }, poco.Foo);
        }

        [Fact]
        public void Test_Object_Encryption_RoundTrip()
        {
            var settings = GetSettings();
            var pocoPlain = new PocoWithChildObject() { Foo = new ChildObject
            {
                IntValue = 3,
                StringValue = "hello"
            } };

            var json = JsonConvert.SerializeObject(pocoPlain, settings);

            Assert.Contains("__crypt", json);

            var poco = JsonConvert.DeserializeObject<PocoWithChildObject>(json, settings);
            Assert.Equal(new ChildObject
            {
                IntValue = 3,
                StringValue = "hello"
            }, poco.Foo);
        }

        [Fact]
        public void Test_Null_Encryption_RoundTrip()
        {
            var settings = GetSettings();
            var pocoPlain = new Poco2 { Foo = null };

            var json = JsonConvert.SerializeObject(pocoPlain, settings);

            Assert.Contains("__crypt", json);

            var poco = JsonConvert.DeserializeObject<Poco2>(json, settings);
            Assert.Null(poco.Foo);
        }

        private JsonSerializerSettings GetSettings()
        {
            var cryptoProviders = new Dictionary<string, ICryptoProvider>
            {
                {
                    "AesProvider", new AesCryptoProvider(new InsecureKeyStore(
                        new KeyValuePair<string, string>("publickey", "!mysecretkey#9^5usdk39d&dlf)03sL"),
                        new KeyValuePair<string, string>("myauthsecret", "mysecret")))
                    {
                        PublicKeyName = "publickey",
                        SigningKeyName = "myauthsecret"
                    }
                }
            };

            return new JsonSerializerSettings
            {
                ContractResolver = new EncryptedFieldContractResolver(cryptoProviders)
            };
        }

        public class Poco3
        {
            [EncryptedField(Provider = "AesProvider")]
            public string Bar { get; set; }
            public int Foo { get; set; }
        }

        public class Poco
        {
            [EncryptedField(Provider = "AesProvider")]
            public string Bar { get; set; }
            public int Foo { get; set; }
        }

        public class Poco1
        {
            [EncryptedField(Provider = "AesProvider")]
            public int Foo { get; set; }
        }

        public class Poco2
        {
            [EncryptedField(Provider = "AesProvider")]
            public List<int> Foo { get; set; }
        }

        public class PocoWithChildObject
        {
            [EncryptedField(Provider = "AesProvider")]
            public ChildObject Foo { get; set; }
        }

        public class ChildObject
        {
            public string StringValue { get; set; }

            public int IntValue { get; set; }

            public override bool Equals(object obj)
            {
                var that = obj as ChildObject;
                if (obj == null) return false;
                return that != null && (IntValue == that.IntValue && StringValue == that.StringValue);
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
