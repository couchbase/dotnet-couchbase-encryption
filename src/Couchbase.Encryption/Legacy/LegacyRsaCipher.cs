using System.Security.Cryptography;
using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption.Legacy
{
    public class LegacyRsaCipher : IEncryptionAlgorithm
    {
        private const bool UseOaepPadding = true;

        public int KeySize { get; set; } = 2048;

        public string Algorithm { get; } = "RSA-2048-OAEP-SHA1";

        public byte[] Decrypt(byte[] key, byte[] cipherText, byte[] associatedData)
        {
            using var rsa = new RSACryptoServiceProvider(KeySize);
            var privateKey = key.FromBytes(false);
            rsa.ImportParameters(privateKey);

            return rsa.Decrypt(cipherText, UseOaepPadding);
        }

        public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] associatedData)
        {
            throw new System.NotImplementedException();
        }
    }
}