using System;
using System.Text;
using Couchbase.Encryption.Errors;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Couchbase.Encryption
{
    public static class JObjectExtensions
    {
        public static void EncryptField(this JObject jsonJObject, ICryptoManager cryptoManager, string path)
        {
            var jToken = jsonJObject.SelectToken(path);
            var rawBytes = Encoding.UTF8.GetBytes(jToken.ToString());
            var encrypted = cryptoManager.Encrypt(rawBytes);

            jsonJObject.Property(path).Remove();
            jsonJObject.Add(new JProperty(cryptoManager.Mangle(path), encrypted.ToJObject()));
        }

        public static void DecryptField<T>(this JObject jsonJObject, ICryptoManager cryptoManager, string path)
        {
            var jToken = jsonJObject.SelectToken(cryptoManager.Mangle(path));
            var kid = jToken.SelectToken(EncryptionField.KeyIdentifier).Value<string>();
            var cipherText = jToken.SelectToken(EncryptionField.CipherText).Value<string>();
            var alg = jToken.SelectToken(EncryptionField.Algorithm).Value<string>();

            var decryptedBytes = cryptoManager.Decrypt(new EncryptionResult
            {
                Alg = alg,
                Kid = kid,
                Ciphertext = cipherText
            });

            var rawText = Encoding.UTF8.GetString(decryptedBytes);
            jsonJObject.Property(cryptoManager.Mangle(path)).Remove();

            var typeCode = Type.GetTypeCode(typeof(T));
            if (typeCode == TypeCode.String)
            {
                jsonJObject.Add(new JProperty(path, rawText));
            }
            else
            {
                var value = JsonConvert.DeserializeObject(rawText);
                jsonJObject.Add(new JProperty(path, value));
            }
        }

        internal static byte[] Decrypt(this JObject encrypted, ICryptoManager cryptoManager, string signingKeyName)
        {
#pragma warning disable 618
            var sig = encrypted.SelectToken(EncryptionField.Signature).Value<string>();
#pragma warning restore 618
            var ciphertext = encrypted.SelectToken(EncryptionField.CipherText).Value<string>();
            var alg = encrypted.SelectToken(EncryptionField.Algorithm).Value<string>();
#pragma warning disable 618
            var iv = encrypted.SelectToken(EncryptionField.InitializationVector).Value<string>();
#pragma warning restore 618
            var kid = encrypted.SelectToken(EncryptionField.KeyIdentifier).Value<string>();

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

        public static void DecryptLegacyRsa<T>(this JObject encrypted, ICryptoManager cryptoManager, string path)
        {
            var cryptoField = encrypted.SelectToken(path);
            var kid = cryptoField.SelectToken(EncryptionField.KeyIdentifier).Value<string>();
            var ciphertext = cryptoField.SelectToken(EncryptionField.CipherText).Value<string>();
            var alg = cryptoField.SelectToken(EncryptionField.Algorithm).Value<string>();

            var unencrypted = cryptoManager.Decrypt(new EncryptionResult
            {
                Alg = alg,
                Ciphertext = ciphertext,
                Kid = kid
            });

            var value = JsonConvert.DeserializeObject<T>(Encoding.UTF8.GetString(unencrypted));
            encrypted.Property(path).Remove();

            var typeCode = Type.GetTypeCode(typeof(T));
            var propertyName = path.Replace("__crypt_", "");

            if (value is System.Collections.IList)
            {
                encrypted.Add(propertyName, new JArray(value));
            }
            else if (typeCode == TypeCode.Object)
            {
                encrypted.Add(propertyName, JObject.FromObject(value));
            }
            else
            {
                encrypted.Add(propertyName, new JValue(value));
            }
        }

        public static void DecryptLegacyAes256<T>(this JObject encrypted, ICryptoManager cryptoManager, string signingKeyName, string path)
        {
            var cryptoField = (JObject)encrypted.SelectToken(path);
            var encryptResult = Decrypt(cryptoField, cryptoManager, signingKeyName);

            var value = JsonConvert.DeserializeObject<T>(Encoding.UTF8.GetString(encryptResult));
            encrypted.Property(path).Remove();

            var typeCode = Type.GetTypeCode(typeof(T));
            var propertyName = path.Replace("__crypt_", "");

            if (value is System.Collections.IList)
            {
                encrypted.Add(propertyName, new JArray(value));
            }
            else if (typeCode == TypeCode.Object)
            {
                encrypted.Add(propertyName, JObject.FromObject(value));
            }
            else
            {
                encrypted.Add(propertyName, new JValue(value));
            }
        }
    }
}
