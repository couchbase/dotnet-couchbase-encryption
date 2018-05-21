using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Couchbase.Extensions.Encryption.Providers
{
    public class AesCryptoProvider : CryptoProviderBase
    {
        public AesCryptoProvider(IKeystoreProvider keystore) : this()
        {
            KeyStore = keystore;
        }

        public AesCryptoProvider()
        {
            ProviderName = "AES-256-HMAC-SHA256";
        }

        public override byte[] Decrypt(byte[] encryptedBytes, byte[] iv, string keyName = null)
        {
            var key = KeyStore.GetKey(keyName ?? PublicKeyName);

            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;

                var decrypter = aes.CreateDecryptor(aes.Key, aes.IV);
                using (var ms = new MemoryStream(encryptedBytes))
                {
                    using (var cs = new CryptoStream(ms, decrypter, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        var value = sr.ReadToEnd();
                        return System.Text.Encoding.UTF8.GetBytes(value);
                    }
                }
            }
        }

        public override byte[] Encrypt(byte[] plainBytes, out byte[] iv)
        {
            var key = KeyStore.GetKey(PublicKeyName);

            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.GenerateIV();
                iv = aes.IV;

                aes.Mode = CipherMode.CBC;
                var encrypter = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encrypter, CryptoStreamMode.Write))
                    {
                        cs.Write(plainBytes, 0, plainBytes.Length);
                    }
                    return ms.ToArray();
                }
            }
        }

        public override bool RequiresAuthentication =>true;
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
