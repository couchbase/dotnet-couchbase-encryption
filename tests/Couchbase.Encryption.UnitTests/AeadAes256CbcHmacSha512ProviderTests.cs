using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Couchbase.Encryption.Internal;
using Couchbase.Encryption.UnitTests.Utils;
using Newtonsoft.Json;
using Xunit;

namespace Couchbase.Encryption.UnitTests
{
    public class AeadAes256CbcHmacSha512ProviderTests
    {
        private static byte[] keyBytes = ("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" +
                                          "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f" +
                                          "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f" +
                                          "30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f").StringToByteArray();

        private byte[] Iv = ("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04").StringToByteArray();

        private static Keyring KeyRing = new Keyring(new IKey[]
        {
            new Key("test-key", keyBytes)
        });

        [Fact]
        public void Test_Encrypt_And_Decrypt()
        {
            var plainText = Encoding.UTF8.GetBytes("\"The enemy knows the system.\"");
            var encrypted = new EncryptionResult
            {
                Alg = "AEAD_AES_256_CBC_HMAC_SHA512",
                Kid = "test-key",
                CipherText =
                    "GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk="
            };
            var provider = new AeadAes256CbcHmacSha512Provider(new AeadAes256CbcHmacSha512Cipher(new FakeRandomNumberGenerator(Iv)), KeyRing);
            var cryptoManager = DefaultCryptoManager.Builder()
                .Decrypter(provider.Decryptor())
                .DefaultEncryptor(provider.Encryptor("test-key"))
                .Build();

            var actual = cryptoManager.Encrypt(plainText);
            Assert.Equal(JsonConvert.SerializeObject(encrypted), JsonConvert.SerializeObject(actual));
            Assert.Equal(plainText, cryptoManager.Decrypt(encrypted));
        }
    }
}
