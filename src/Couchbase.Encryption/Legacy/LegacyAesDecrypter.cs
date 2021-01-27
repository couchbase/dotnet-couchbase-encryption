using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption.Legacy
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

        public string Algorithm => _cipher.Algorithm;

        public byte[] Decrypt(EncryptionResult encrypted)
        {
            var key = _keyring.GetOrThrow(encrypted.Kid);
            var cipherBytes = System.Convert.FromBase64String(encrypted.Ciphertext);
            var plainBytes = _cipher.Decrypt(key.Bytes, cipherBytes, encrypted.Iv);
            return plainBytes;
        }
    }
}
