using System;
using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption.Legacy
{
    internal class LegacyRsaDecrypter : IDecrypter
    {
        private readonly IEncryptionAlgorithm _cipher;
        private readonly IKeyring _keyring;

        public LegacyRsaDecrypter(IKeyring keyring, IEncryptionAlgorithm cipher)
        {
            _keyring = keyring;
            _cipher = cipher;
        }

        public string Algorithm => _cipher.Algorithm;

        public byte[] Decrypt(EncryptionResult encrypted)
        {
            var key = _keyring.GetOrThrow(encrypted.Kid);
            var cipherBytes = Convert.FromBase64String(encrypted.Ciphertext);
            var plainBytes = _cipher.Decrypt(key.Bytes, cipherBytes, encrypted.Iv);
            return plainBytes;
        }
    }
}
