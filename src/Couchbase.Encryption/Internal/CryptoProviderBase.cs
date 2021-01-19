using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Couchbase.Encryption.Internal
{
    public abstract class CryptoProviderBase
    {
        public abstract byte[] Decrypt(byte[] key, byte[] encryptedBytes, byte[] iv, string keyName = null);

        public abstract byte[] Encrypt(byte[] key, byte[] plainBytes, out byte[] iv);

        public virtual byte[] GetSignature(byte[] key, byte[] cipherBytes)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(cipherBytes);
            }
        }

        public string ProviderName { get; set; }
        public virtual string PublicKeyName { get; set; }
        public virtual string PrivateKeyName { get; set; }
        public string SigningKeyName { get; set; }
        public abstract bool RequiresAuthentication { get; }
        public string AlgorithmName { get; protected set; }
    }
}
