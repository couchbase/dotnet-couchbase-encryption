using System;

namespace Couchbase.Encryption.Internal
{
    internal class LegacyAesDecrypter : IDecrypter
    {
        private readonly IEncryptionAlgorithm _cipher;
        private readonly IKeyring _keyring;

        public LegacyAesDecrypter(IKeyring keyring, IEncryptionAlgorithm cipher)
        {
            _keyring = keyring;
            _cipher = cipher;
        }

        internal byte[] AssociatedData => new byte[0];

        public string Algorithm => _cipher.Algorithm;

        public byte[] Decrypt(EncryptionResult encrypted)
        {
            var key = _keyring.GetOrThrow(encrypted.Kid);
            var cipherBytes = System.Convert.FromBase64String(encrypted.Ciphertext);
            var plainBytes = _cipher.Decrypt(key.Bytes, cipherBytes, AssociatedData);
            return plainBytes;
        }
    }
}
