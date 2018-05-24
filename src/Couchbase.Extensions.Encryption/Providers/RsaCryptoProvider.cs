using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace Couchbase.Extensions.Encryption.Providers
{
    public class RsaCryptoProvider : CryptoProviderBase
    {
        private const bool UseOaepPadding = true;

        public RsaCryptoProvider(IKeystoreProvider keyStore)
            : this()
        {
            KeyStore = keyStore;
        }

        public RsaCryptoProvider()
        {
            AlgorithmName = "RSA-2048-OAEP";
            KeySize = 2048;
#if NETSTANDARD
            Padding = RSAEncryptionPadding.OaepSHA512;
#endif
        }

        public IKeystoreProvider KeyStore { get; set; }

        public override byte[] Decrypt(byte[] cipherBytes, byte[] iv = null, string keyName = null)
        {
#if NETSTANDARD
            using (var rsa = new RSACng(KeySize))
            {
                var privateKey = GetParameters(KeyStore.GetKey(PrivateKeyName));
                rsa.ImportParameters(privateKey);

                return rsa.Decrypt(cipherBytes, Padding);
            }
#else
            using (var rsa = new RSACryptoServiceProvider(KeySize))
            {
                var privateKey = GetParameters(KeyStore.GetKey(PrivateKeyName));
                rsa.ImportParameters(privateKey);

                return rsa.Decrypt(cipherBytes, UseOaepPadding);
            }
#endif
        }

        public override byte[] Encrypt(byte[] plainBytes, out byte[] iv)
        {
            iv = null;//iv does not apply here
#if NETSTANDARD
            using (var rsa = new RSACng(KeySize))
            {
                var publicKey = GetParameters(KeyStore.GetKey(PublicKeyName));
                rsa.ImportParameters(publicKey);

                return rsa.Encrypt(plainBytes, Padding);
            }
#else
            using (var rsa = new RSACryptoServiceProvider(KeySize))
            {
                var publicKey = GetParameters(KeyStore.GetKey(PublicKeyName));
                rsa.ImportParameters(publicKey);

                return rsa.Encrypt(plainBytes, UseOaepPadding);
            }
#endif
        }

        public object Decrypt(object value, string keyName = null)
        {
#if NETSTANDARD
            using (var rsa = new RSACng(KeySize))
            {
                var privateKey = GetParameters(KeyStore.GetKey(PrivateKeyName));
                rsa.ImportParameters(privateKey);

                var cypherBytes = Convert.FromBase64String(value.ToString());
                var plainBytes = rsa.Decrypt(cypherBytes, Padding);

                return Encoding.UTF8.GetString(plainBytes);
            }
#else
            using (var rsa = new RSACryptoServiceProvider(KeySize))
            {
                var privateKey = GetParameters(KeyStore.GetKey(PrivateKeyName));
                rsa.ImportParameters(privateKey);

                var cypherBytes = Convert.FromBase64String(value.ToString());
                var plainBytes = rsa.Decrypt(cypherBytes, UseOaepPadding);

                return Encoding.UTF8.GetString(plainBytes);
            }
#endif
        }

        public object Encrypt(object value)
        {
#if NETSTANDARD
            using (var rsa = new RSACng(KeySize))
            {
                var publicKey = GetParameters(KeyStore.GetKey(PublicKeyName));
                rsa.ImportParameters(publicKey);


                var plainBytes = Encoding.UTF8.GetBytes(value.ToString());
                var cypherBytes = rsa.Encrypt(plainBytes, Padding);

                return Convert.ToBase64String(cypherBytes);
            }
#else
            using (var rsa = new RSACryptoServiceProvider(KeySize))
            {
                var publicKey = GetParameters(KeyStore.GetKey(PublicKeyName));
                rsa.ImportParameters(publicKey);

                var plainBytes = Encoding.UTF8.GetBytes(value.ToString());
                var cypherBytes = rsa.Encrypt(plainBytes, UseOaepPadding);

                return Convert.ToBase64String(cypherBytes);
            }
#endif
        }

        private RSAParameters GetParameters(string key)
        {
            using (var reader = new StringReader(key))
            {
                var serializer = new XmlSerializer(typeof(RSAParameters));
                return (RSAParameters)serializer.Deserialize(reader);
            }
        }

        public override bool RequiresAuthentication => false;

        public int KeySize { get; set; }

#if NETSTANDARD
        public RSAEncryptionPadding Padding { get; set; }
#endif
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
