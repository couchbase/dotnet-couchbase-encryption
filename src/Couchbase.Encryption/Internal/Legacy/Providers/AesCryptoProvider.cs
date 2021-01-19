using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Couchbase.Encryption.Internal.Legacy.Providers
{
    internal class AesCryptoProvider : CryptoProviderBase
    {
        //supports 256 bit keys
        public const int SupportedKeySize = 32;

        public AesCryptoProvider(IKeystoreProvider keystore)
            : this()
        {
            KeyStore = keystore;
        }

        public AesCryptoProvider()
        {
            AlgorithmName = "AES-256-CBC-HMAC-SHA256";
        }

        public override byte[] Decrypt(byte[] encryptedBytes, byte[] iv, string keyName = null)
        {
            //sanity check #1
            keyName = keyName ?? PublicKeyName;
            if (string.IsNullOrWhiteSpace(keyName))
            {
                throw new CryptoProviderMissingPublicKeyException(ProviderName);
            }

            //sanity check #2
            var key = KeyStore.GetKey(keyName);
            if (key == null || key.Length != SupportedKeySize)
            {
                var actualKeySize = key?.Length * 8 ?? 0;
                throw new CryptoProviderKeySizeException(ProviderName,  SupportedKeySize * 8, actualKeySize);
            }

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
            //sanity check #1
            if (string.IsNullOrWhiteSpace(PublicKeyName))
            {
                throw new CryptoProviderMissingPublicKeyException(ProviderName);
            }

            //sanity check #2
            var key = KeyStore.GetKey(PublicKeyName);
            if (key == null || key.Length != SupportedKeySize)
            {
                var actualKeySize = key?.Length * 8 ?? 0;
                throw new CryptoProviderKeySizeException(ProviderName, SupportedKeySize * 8, actualKeySize);
            }

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
