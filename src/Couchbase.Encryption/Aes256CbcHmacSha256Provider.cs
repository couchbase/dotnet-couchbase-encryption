using Couchbase.Encryption.Internal;
using Couchbase.Encryption.Legacy;

namespace Couchbase.Encryption
{
    public sealed class Aes256CbcHmacSha256Provider
    {
        private readonly IKeyring _keyring;
        private readonly IEncryptionAlgorithm _cipher;

        public Aes256CbcHmacSha256Provider(IKeyring keyring, IEncryptionAlgorithm cipher)
        {
            _keyring = keyring;
            _cipher = cipher;
        }

        public IDecrypter Decrypter()
        {
            return new LegacyAesDecrypter(_keyring, _cipher);
        }
    }
}
