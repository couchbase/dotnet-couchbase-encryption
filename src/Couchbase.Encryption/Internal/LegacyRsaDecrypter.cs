using System;
using System.Security.Cryptography;

namespace Couchbase.Encryption.Internal
{
    internal class LegacyRsaDecrypter : CryptoProviderBase
    {
        public override byte[] Decrypt(byte[] key, byte[] encryptedBytes, byte[] iv, string keyName = null)
        {
            throw new NotImplementedException();
        }

        public override byte[] Encrypt(byte[] key, byte[] plainBytes, out byte[] iv)
        {
            throw new NotImplementedException();
        }

        public override bool RequiresAuthentication { get; }
    }
}
