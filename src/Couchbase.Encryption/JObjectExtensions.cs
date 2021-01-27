using System;
using System.Text;
using Couchbase.Encryption.Errors;
using Newtonsoft.Json.Linq;

namespace Couchbase.Encryption
{
    public static class JObjectExtensions
    {
        public static byte[] Decrypt(this JObject encrypted, string signingKeyName,
            ICryptoManager cryptoManager)
        {
            var sig = encrypted.SelectToken("sig").Value<string>();
            var ciphertext = encrypted.SelectToken("ciphertext").Value<string>();
            var alg = encrypted.SelectToken("alg").Value<string>();
            var iv = encrypted.SelectToken("iv").Value<string>();
            var kid = encrypted.SelectToken("kid").Value<string>();

            var kidBytes = Encoding.UTF8.GetBytes(kid);
            var algBytes = Encoding.UTF8.GetBytes(alg);
            var ivBytes = Convert.FromBase64String(iv);
            var cipherBytes = Convert.FromBase64String(ciphertext);

            var buffer = new byte[kidBytes.Length + algBytes.Length + ivBytes.Length + cipherBytes.Length];
            Buffer.BlockCopy(kidBytes, 0, buffer, 0, kidBytes.Length);
            Buffer.BlockCopy(algBytes, 0, buffer, kidBytes.Length, algBytes.Length);
            Buffer.BlockCopy(ivBytes, 0, buffer, kidBytes.Length + algBytes.Length, ivBytes.Length);
            Buffer.BlockCopy(cipherBytes, 0, buffer, kidBytes.Length + algBytes.Length + ivBytes.Length, cipherBytes.Length);

            var signature = cryptoManager.Encrypt(buffer, signingKeyName);
            if (sig != signature.Ciphertext) throw new DecryptionFailureException();

            return cryptoManager.Decrypt(new EncryptionResult
            {
                Alg = alg,
                Kid = kid,
                Ciphertext = ciphertext,
                Iv = Convert.FromBase64String(iv)
            });
        }

        private static byte[] DecryptRsa(this JObject encrypted)
        {
            throw new NotImplementedException();
        }

        private static byte[] DecryptAes256(this JObject encrypted, string signingKeyName, IKeyring keyring,
            ICryptoManager cryptoManager)
        {
            var sig = encrypted.SelectToken("sig").Value<string>();
            var ciphertext = encrypted.SelectToken("ciphertext").Value<string>();
            var alg = encrypted.SelectToken("alg").Value<string>();
            var iv = encrypted.SelectToken("iv").Value<string>();
            var kid = encrypted.SelectToken("kid").Value<string>();

            var signMe = kid + alg + iv + ciphertext;
            var buffer = Encoding.UTF8.GetBytes(signMe);

            var signature = cryptoManager.Encrypt(buffer, signingKeyName);
            if (sig != signature.Ciphertext) throw new DecryptionFailureException();

            return cryptoManager.Decrypt(new EncryptionResult
            {
                Alg = alg,
                Kid = kid,
                Ciphertext = ciphertext,
                Iv = Convert.FromBase64String(iv)
            });
        }
    }
}
