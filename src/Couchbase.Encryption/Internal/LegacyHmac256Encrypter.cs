using System;

namespace Couchbase.Encryption.Internal
{
    internal class LegacyHmac256Encrypter : IEncrypter
    {
        private readonly LegacyHmac256Cipher _cipher;
        private readonly IKeyring _keyring;
        private readonly string _signingKeyName;

        public LegacyHmac256Encrypter(LegacyHmac256Cipher cipher, IKeyring keyring, string signingKeyName)
        {
            _cipher = cipher;
            _keyring = keyring;
            _signingKeyName = signingKeyName;
        }

        public EncryptionResult Encrypt(byte[] plaintext)
        {
            var key = _keyring.GetOrThrow(_signingKeyName);
            return new EncryptionResult
            {
                Alg = _cipher.Algorithm,
                Ciphertext = Convert.ToBase64String(_cipher.Encrypt(key.Bytes, plaintext, Array.Empty<byte>())),
                Kid = _signingKeyName
            };
        }
    }
}
