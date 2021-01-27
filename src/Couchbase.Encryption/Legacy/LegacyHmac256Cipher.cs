using System;
using System.Security.Cryptography;
using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption.Legacy
{
    internal class LegacyHmac256Cipher : IEncryptionAlgorithm
    {
        public string Algorithm => "HMAC256";

        public byte[] Decrypt(byte[] key, byte[] cipherText, byte[] associatedData)
        {
            throw new NotImplementedException();
        }

        public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] associatedData)
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(plaintext);
        }
    }
}
