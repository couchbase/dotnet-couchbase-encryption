using System;
using System.Text;
using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption
{
    internal class Encrypter : IEncrypter
    {
        private readonly IEncryptionAlgorithm _cipher;
        private readonly IKey _key;

        public Encrypter(IEncryptionAlgorithm cipher, IKey key)
        {
            _cipher = cipher;
            _key = key;
        }

        internal byte[] AssociatedData { get; set; } = Array.Empty<byte>();

        public EncryptionResult Encrypt(byte[] plaintext)
        {
            var encrypted = _cipher.Encrypt(_key.Bytes, plaintext, AssociatedData);
            return new EncryptionResult
            {
                Alg = _cipher.Algorithm,
                CipherText = System.Convert.ToBase64String(encrypted),
                Kid = _key.Id
            };
        }
    }
}
