using System.Security.Cryptography;

namespace Couchbase.Encryption.Internal.Legacy
{
    internal abstract class CryptoProviderBase : ICryptoProvider
    {
        public IKeystoreProvider KeyStore { get; set; }

        public abstract byte[] Decrypt(byte[] encryptedBytes, byte[] iv, string keyName = null);

        public abstract byte[] Encrypt(byte[] plainBytes, out byte[] iv);

        public virtual byte[] GetSignature(byte[] cipherBytes)
        {
            if (string.IsNullOrWhiteSpace(SigningKeyName))
            {
                throw new CryptoProviderMissingSigningKeyException(ProviderName);
            }
            var password = KeyStore.GetKey(SigningKeyName);
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            using (var hmac = new HMACSHA256(passwordBytes))
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

#region [License information]
/* ************************************************************

 *    Copyright (c) 2018 Couchbase, Inc.
 *
 *    Use of this software is subject to the Couchbase Inc.
 *    Enterprise Subscription License Agreement which may be found
 *    at https://www.couchbase.com/ESLA-11132015.

 * ************************************************************/
#endregion
