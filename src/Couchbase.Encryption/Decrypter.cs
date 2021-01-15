using System.Text;
using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption
{
    internal class Decrypter : IDecrypter
    {
        private readonly IEncryptionAlgorithm _cipher;
        private readonly IKeyring _keyring;

        public Decrypter(IEncryptionAlgorithm cipher, IKeyring keyring)
        {
            _cipher = cipher;
            _keyring = keyring;
        }

        internal byte[] AssociatedData { get; set; }

        public string Algorithm => _cipher.Algorithm;

        public byte[] Decrypt(EncryptionResult encrypted)
        {
            var key = _keyring.GetOrThrow(encrypted.Kid);
            var cipherBytes = System.Convert.FromBase64String(encrypted.CipherText);
            var plainBytes = _cipher.Decrypt(key.Bytes, cipherBytes, AssociatedData);
            return plainBytes;
        }
    }
}
