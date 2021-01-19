using System;
using System.IO;
using System.Security.Cryptography;

namespace Couchbase.Encryption.Internal
{
    internal class Aes256CbcHmacSha256Cipher : IEncryptionAlgorithm
    {
        private readonly byte[] _iv;

        public Aes256CbcHmacSha256Cipher(byte[] iv)
        {
            _iv = iv;
        }

        public string Algorithm => "AES-256-CBC-HMAC-SHA256";

        public byte[] Decrypt(byte[] key, byte[] cipherText, byte[] associatedData)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = _iv;
            aes.Mode = CipherMode.CBC;

            var decrypter = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(cipherText);
            using var cs = new CryptoStream(ms, decrypter, CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            var value = sr.ReadToEnd();
            return System.Text.Encoding.UTF8.GetBytes(value);
        }

        public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] associatedData)
        {
            throw new NotImplementedException();
        }
    }
}
