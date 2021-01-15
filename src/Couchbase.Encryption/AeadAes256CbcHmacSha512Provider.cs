using System.Security.Cryptography;
using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption
{
    public class AeadAes256CbcHmacSha512Provider
    {
        private readonly IEncryptionAlgorithm _cipher;
        private readonly IKeyring _keyring;

        private static readonly byte[] NoAssociatedData = new byte[0];

        public AeadAes256CbcHmacSha512Provider(IEncryptionAlgorithm cipher, IKeyring keyring)
        {
            _cipher = cipher;
            _keyring = keyring;
        }

        public IEncrypter Encryptor(string keyId)
        {
            return new Encrypter(_cipher, _keyring.Get(keyId))
            {
                AssociatedData = NoAssociatedData
            };
        }

        public IDecrypter Decryptor()
        {
            return new Decrypter(_cipher, _keyring)
            {
                AssociatedData = NoAssociatedData
            };
        }
    }
}
