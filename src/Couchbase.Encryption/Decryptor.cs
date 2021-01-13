using System.Text;
using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption
{
    internal class Decryptor : IDecryptor
    {
        private readonly IEncryptionAlgorithm _cipher;
        private readonly IKey _key;

        public Decryptor(IEncryptionAlgorithm cipher, IKey key)
        {
            _cipher = cipher;
            _key = key;
        }

        internal byte[] AssociatedData { get; set; }

        public string Algorithm => _cipher.Algorithm;

        public byte[] Decrypt(EncryptionResult encrypted)
        {
            var cipherBytes = Encoding.UTF8.GetBytes(encrypted.CipherText);
            var plainBytes = _cipher.Decrypt(_key.Bytes, cipherBytes, AssociatedData);
            return plainBytes;
        }
    }
}
