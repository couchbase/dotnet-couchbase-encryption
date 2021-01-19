using System;
using System.Collections.Generic;
using Couchbase.Encryption.Attributes;
using Couchbase.Encryption.Internal;
using Couchbase.Encryption.UnitTests.Utils;
using Newtonsoft.Json;
using Xunit;

namespace Couchbase.Encryption.UnitTests
{
    public class EncryptedFieldAttributeTests
    {
        private static readonly byte[] KeyBytes = ("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" +
                                                   "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f" +
                                                   "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f" +
                                                   "30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f").StringToByteArray();

        private static readonly byte[] Iv = ("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04").StringToByteArray();

        private static readonly Keyring KeyRing = new Keyring(new IKey[]
        {
            new Key("test-key", KeyBytes)
        });


        [Fact]
        public void Test_TestSerialize()
        {
            var jsonSerializerSettings = GetJsonSerializerSettings();

            var poco = new Person
            {
                Age = 10,
                IsActive = false,
                Name = "Tom Jones"
            };

            var json = JsonConvert.SerializeObject(poco, jsonSerializerSettings);

            Assert.NotNull(json);
        }


        [Fact]
        public void Test_Test_Deserialize()
        {
            var jsonSerializerSettings = GetJsonSerializerSettings();

            var poco = new Person
            {
                Age = 10,
                IsActive = false,
                Name = "Tom Jones"
            };

            var encryptedJson = JsonConvert.SerializeObject(poco, jsonSerializerSettings);
            var decryptedPoco = JsonConvert.DeserializeObject<Person>(encryptedJson, jsonSerializerSettings);

            Assert.True(poco.Equals(decryptedPoco));
        }

        private JsonSerializerSettings GetJsonSerializerSettings()
        {
            var provider = new AeadAes256CbcHmacSha512Provider(new AeadAes256CbcHmacSha512Cipher(new FakeRandomNumberGenerator(Iv)), KeyRing);
            var cryptoManager = DefaultCryptoManager.Builder()
                .Decrypter(provider.Decrypter())
                .DefaultEncrypter(provider.Encrypter("test-key"))
                .Build();

            return new JsonSerializerSettings
            {
                ContractResolver = new EncryptedFieldContractResolver(cryptoManager)
            };
        }
    }

    public class Person : IEquatable<Person>
    {
        [EncryptedField(KeyName = "test-key")]
        public string Name { get; set; }

        public int Age { get; set; }

        public bool IsActive { get; set; }

        public List<Dog> Doggies { get; set; }

        public bool Equals(Person other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Name == other.Name && Age == other.Age && IsActive == other.IsActive && Equals(Doggies, other.Doggies);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((Person) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (Name != null ? Name.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ Age;
                hashCode = (hashCode * 397) ^ IsActive.GetHashCode();
                hashCode = (hashCode * 397) ^ (Doggies != null ? Doggies.GetHashCode() : 0);
                return hashCode;
            }
        }
    }

    public class Dog : IEquatable<Dog>
    {
    public string Name { get; set; }

    public string Color { get; set; }

    public string Breed { get; set; }

    public int Age { get; set; }

    public bool Equals(Dog other)
    {
        if (ReferenceEquals(null, other)) return false;
        if (ReferenceEquals(this, other)) return true;
        return Name == other.Name && Color == other.Color && Breed == other.Breed && Age == other.Age;
    }

    public override bool Equals(object obj)
    {
        if (ReferenceEquals(null, obj)) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != this.GetType()) return false;
        return Equals((Dog) obj);
    }

    public override int GetHashCode()
    {
        unchecked
        {
            var hashCode = (Name != null ? Name.GetHashCode() : 0);
            hashCode = (hashCode * 397) ^ (Color != null ? Color.GetHashCode() : 0);
            hashCode = (hashCode * 397) ^ (Breed != null ? Breed.GetHashCode() : 0);
            hashCode = (hashCode * 397) ^ Age;
            return hashCode;
        }
    }
    }
}
