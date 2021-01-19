using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Couchbase.Encryption.Errors;

namespace Couchbase.Encryption.Internal
{
    public sealed class AeadAes256CbcHmacSha512Cipher : IEncryptionAlgorithm
    {
        private static int IvLength = 16;
        private static int AuthTagLength = 32;

        private readonly AesCryptoServiceProvider _aesCryptoProvider;
        private readonly IRandomNumberGenerator _randomNumberGenerator;

        public string Algorithm => "AEAD_AES_256_CBC_HMAC_SHA512";

        public AeadAes256CbcHmacSha512Cipher() : this(new DefaultRandomNumberGenerator())
        {
        }

        public AeadAes256CbcHmacSha512Cipher(IRandomNumberGenerator randomNumberGenerator)
        {
            _randomNumberGenerator = randomNumberGenerator;
            _aesCryptoProvider = new AesCryptoServiceProvider
            {
                BlockSize = 128,
                KeySize = 256,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC
            };
        }

        public byte[] Decrypt(byte[] key, byte[] cipherText, byte[] associatedData)
        {
            CheckKeyLength(key);

            var macKey = new Span<byte>(key).Slice(0, 32);
            var encKey = new Span<byte>(key).Slice(32, 32);

            var authTagOffset = cipherText.Length - AuthTagLength;
            var enc = cipherText.AsSpan(0, authTagOffset);
            var authTag = cipherText.AsSpan(authTagOffset, AuthTagLength);

            var associatedDataLengthInBits = GetDataLengthInBits(associatedData);
            var computedMac = HmacSha512(macKey.ToArray(), associatedData, enc.ToArray(), associatedDataLengthInBits);
            var computedMacAuthTag = new Span<byte>(computedMac).Slice(0, AuthTagLength).ToArray();

            if (!VerifyIntegrity(authTag.ToArray(), computedMacAuthTag))
            {
                throw new InvalidCiphertextException("Failed to authenticate the cipherText and associated data.");
            }

            return DecryptAesCbcPkcs7(encKey.ToArray(), enc.ToArray());
        }

        private bool VerifyIntegrity(byte[] authTag, byte[] computedMacAuthTag)
        {
            if (authTag.Length != computedMacAuthTag.Length) return false;

            var result = 0;
            for (var i = 0; i < authTag.Length; i++)
            {
                result |= authTag[i] ^ computedMacAuthTag[i];
            }

            return result == 0;
        }

        private byte[] DecryptAesCbcPkcs7(byte[] key, byte[] cipherText)
        {
            var iv = new Span<byte>(cipherText).Slice(0, IvLength).ToArray();

            using var decryptor = _aesCryptoProvider.CreateDecryptor(key, iv);
            return decryptor.TransformFinalBlock(cipherText.ToArray(), IvLength, cipherText.Length - IvLength);
        }

        public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] associatedData)
        {
            CheckKeyLength(key);

            var macKey = new Span<byte>(key).Slice(0, 32);
            var encKey = new Span<byte>(key).Slice(32, 32);

            var enc = EncryptAesCbcPkcs7(encKey, plaintext);
            var associatedDataLengthInBits = GetDataLengthInBits(associatedData);
            var computedMac = HmacSha512(macKey.ToArray(), associatedData, enc, associatedDataLengthInBits);
            var authTag = new Span<byte>(computedMac).Slice(0, AuthTagLength).ToArray();

            return Concat(enc, authTag);
        }

        private byte[] EncryptAesCbcPkcs7(Span<byte> key, byte[] plaintext)
        {
            var iv = new Span<byte>(new byte[IvLength]);
            _randomNumberGenerator.Fill(iv);

            using var encryptor = _aesCryptoProvider.CreateEncryptor(key.ToArray(), iv.ToArray());
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            using var sw = new BinaryWriter(cs);
            sw.Write(plaintext);
            cs.FlushFinalBlock();

            return Concat(iv.ToArray(), ms.ToArray());
        }

        private void CheckKeyLength(byte[] key)
        {
            if(key.Length != 64) throw new InvalidCryptoKeyException($"Expected key to be 64 bytes but got {key.Length} bytes.");
        }

        private byte[] Concat(byte[] first, byte[] second)
        {
            var destination = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, destination, 0, first.Length);
            Buffer.BlockCopy(second, 0, destination, first.Length, second.Length);
            return destination;
        }

        //this may not be needed with non-unit test data
        private byte[] GetDataLengthInBits(byte[] bytes)
        {
            var length = BitConverter.GetBytes(bytes.Length * 8L);
            return BitConverter.IsLittleEndian ? length.Reverse().ToArray() : length;
        }

        private byte[] HmacSha512(byte[] key, params byte[][] authenticateMe)
        {
            using var ms = new MemoryStream();
            using var hmacSha512 = new HMACSHA512(key);
            hmacSha512.Initialize();
            foreach (var bytes in authenticateMe)
            {
                ms.Write(bytes);
            }

            return hmacSha512.ComputeHash(ms.ToArray());
        }
    }
}
