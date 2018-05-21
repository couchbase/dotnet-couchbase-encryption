using System.Security.Cryptography;

namespace Couchbase.Extensions.Encryption
{
    public abstract class CryptoProviderBase : ICryptoProvider
    {
        public IKeystoreProvider KeyStore { get; set; }

        public abstract byte[] Decrypt(byte[] encryptedBytes, byte[] iv, string keyName = null);

        public abstract byte[] Encrypt(byte[] plainBytes, out byte[] iv);

        public virtual byte[] GetSignature(byte[] cipherBytes)
        {
            var password = KeyStore.GetKey(SigningKeyName);
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            using (var hmac = new HMACSHA256(passwordBytes))
            {
                return hmac.ComputeHash(cipherBytes);
            }
        }

        public string ProviderName { get; set; }
        public string PublicKeyName { get; set; }
        public string PrivateKeyName { get; set; }
        public string SigningKeyName { get; set; }
        public abstract bool RequiresAuthentication { get; }
    }
}

#region [License information]
/* ************************************************************

 *    Copyright (c) 2018 Couchbase, Inc.
 *
 *    Use of this software is subject to the Couchbase Inc.
 *    Enterprise Subscription License Agreement which may be found
 *    at https://www.couchbase.com/ESLA-11132015.

 * ************************************************************/
#endregion
