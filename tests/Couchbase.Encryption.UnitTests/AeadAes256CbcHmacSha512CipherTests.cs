﻿using System;
using System.Security.Cryptography;
using Couchbase.Encryption.Errors;
using Couchbase.Encryption.Internal;
using Couchbase.Encryption.UnitTests.Utils;
using Xunit;

namespace Couchbase.Encryption.UnitTests
{
    public class AeadAes256CbcHmacSha512CipherTests
    {
        private static readonly byte[] Key = ("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" +
                                              "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f" +
                                              "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f" +
                                              "30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f").StringToByteArray();


        private static readonly byte[] Iv = "1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04".StringToByteArray();

        private static readonly byte[] Plaintext = ("41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20" +
                                                    "6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75" +
                                                    "69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65" +
                                                    "74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62" +
                                                    "65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69" +
                                                    "6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66" +
                                                    "20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f" +
                                                    "75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65").StringToByteArray();

        private static readonly byte[] AssociatedData = ("54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63" +
                                                         "69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20" +
                                                         "4b 65 72 63 6b 68 6f 66 66 73").StringToByteArray();

        private static readonly byte[] CipherText = ("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04" +
                                                    "4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd" +
                                                    "3d d8 d5 d3 02 42 35 26 91 2d a0 37 ec bc c7 bd" +
                                                    "82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2" +
                                                    "e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 6b" +
                                                    "36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1" +
                                                    "1a 09 cc f5 37 0d c8 0b fe cb ad 28 c7 3f 09 b3" +
                                                    "a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e" +
                                                    "31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b" +
                                                    "be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6" +
                                                    "4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf" +
                                                    "2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5").StringToByteArray();

        [Fact]
        public void Test_Encrypt()
        {
            var cipherWithFixedIv = new AeadAes256CbcHmacSha512Cipher(new FakeRandomNumberGenerator(Iv));
            var actualCiphertext = cipherWithFixedIv.Encrypt(Key, Plaintext, AssociatedData);

            Assert.Equal(CipherText, actualCiphertext);
        }

        [Fact]
        public void Test_Decrypt()
        {
            var cipherWithFixedIv = new AeadAes256CbcHmacSha512Cipher(new FakeRandomNumberGenerator(Iv));
            var actualPlainText = cipherWithFixedIv.Decrypt(Key, CipherText, AssociatedData);

            Assert.Equal(Plaintext, actualPlainText);
        }

        [Fact]
        public void Test_AssociatedDataCanBeEmpty()
        {
            var emptyByteArray = Array.Empty<byte>();
            var cipherWithFixedIv = new AeadAes256CbcHmacSha512Cipher(new FakeRandomNumberGenerator(emptyByteArray));
            var cipherText = cipherWithFixedIv.Encrypt(Key, Plaintext, emptyByteArray);
            var roundTripPlainText = new AeadAes256CbcHmacSha512Cipher().Decrypt(Key, cipherText, emptyByteArray);

            Assert.Equal(Plaintext, roundTripPlainText);
        }

        [Fact]
        public void Test_WorksWithRealIvGenerator()
        {
            var cipherWithRandomIv = new AeadAes256CbcHmacSha512Cipher();
            var cipherText = cipherWithRandomIv.Encrypt(Key, Plaintext, AssociatedData);
            var roundTripPlainText = cipherWithRandomIv.Decrypt(Key, cipherText, AssociatedData);

            Assert.Equal(Plaintext, roundTripPlainText);
        }

        [Fact]
        public void Test_DecryptBadAssociatedData()
        {
            var cipherWithFixedIv = new AeadAes256CbcHmacSha512Cipher(new FakeRandomNumberGenerator(Iv));
            var bogusAssociatedData = (byte[])AssociatedData.Clone();
            bogusAssociatedData[0]++;

            Assert.Throws<InvalidCiphertextException>(() => cipherWithFixedIv.Decrypt(Key, CipherText, bogusAssociatedData));
        }

        [Fact]
        public void Test_DecryptBadCipherText()
        {
            var cipherWithFixedIv = new AeadAes256CbcHmacSha512Cipher(new FakeRandomNumberGenerator(Iv));
            var bogusCipherText = (byte[]) CipherText.Clone();
            bogusCipherText[0]++;

            Assert.Throws<InvalidCiphertextException>(() => cipherWithFixedIv.Decrypt(Key, bogusCipherText, AssociatedData));
        }

        [Fact]
        public void Test_DecryptBadKeySize()
        {
            var cipherWithFixedIv = new AeadAes256CbcHmacSha512Cipher(new FakeRandomNumberGenerator(Iv));

            Assert.Throws<InvalidCryptoKeyException>(() => cipherWithFixedIv.Decrypt(new byte[0], CipherText, AssociatedData));
        }


        [Fact]
        public void Test_EncryptBadKeySize()
        {
            var cipherWithFixedIv = new AeadAes256CbcHmacSha512Cipher(new FakeRandomNumberGenerator(Iv));

            Assert.Throws<InvalidCryptoKeyException>(() => cipherWithFixedIv.Encrypt(new byte[0], CipherText, AssociatedData));
        }
    }
}
