using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace Couchbase.Encryption.Internal.Legacy
{
    internal class EncryptableFieldConverter : JsonConverter
    {
        public EncryptableFieldConverter(PropertyInfo targetProperty, Dictionary<string, ICryptoProvider> cryptoProviders, string providerName)
        {
            TargetProperty = targetProperty;
            CryptoProviders = cryptoProviders;
            ProviderName = providerName;
            SerializerSettings =
                new JsonSerializerSettings
                {
                    ContractResolver = new CamelCasePropertyNamesContractResolver()
                };
        }

        public PropertyInfo TargetProperty { get; }

        public Dictionary<string, ICryptoProvider> CryptoProviders { get; set; }

        public string ProviderName { get; set; }

        public JsonSerializerSettings SerializerSettings { get; set; }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var rawJson = JsonConvert.SerializeObject(value, SerializerSettings);

            if (!CryptoProviders.TryGetValue(ProviderName, out var cryptoProvider))
            {
                throw new CryptoProviderNotFoundException(ProviderName);
            }

            var rawBytes = Encoding.UTF8.GetBytes(rawJson);
            try
            {
                var cipherText = cryptoProvider.Encrypt(rawBytes, out var iv);
                var base64CipherText = Convert.ToBase64String(cipherText);

                byte[] signatureBytes = null;
                if (cryptoProvider.RequiresAuthentication)
                {
                    //sig = HMAC256(BASE64(kid + alg + iv + ciphertext))
                    var kidBytes = Encoding.UTF8.GetBytes(cryptoProvider.PublicKeyName);
                    var algBytes = Encoding.UTF8.GetBytes(cryptoProvider.AlgorithmName);
                    var buffer = new byte[kidBytes.Length + algBytes.Length + iv.Length + cipherText.Length];

                    Buffer.BlockCopy(kidBytes, 0, buffer, 0, kidBytes.Length);
                    Buffer.BlockCopy(algBytes, 0, buffer, kidBytes.Length, algBytes.Length);
                    Buffer.BlockCopy(iv, 0, buffer, kidBytes.Length + algBytes.Length, iv.Length);
                    Buffer.BlockCopy(cipherText, 0, buffer, kidBytes.Length + algBytes.Length + iv.Length, cipherText.Length);

                    //sign the entire buffer
                    signatureBytes = cryptoProvider.GetSignature(buffer);
                }

                var token = new JObject(
                    new JProperty("alg", cryptoProvider.AlgorithmName),
                    new JProperty("kid", cryptoProvider.PublicKeyName),
                    new JProperty("ciphertext", base64CipherText));

                if (signatureBytes != null)
                {
                    var base64Sig = Convert.ToBase64String(signatureBytes);
                    token.Add("sig", base64Sig);
                }

                if (iv != null)
                {
                    token.Add("iv", Convert.ToBase64String(iv));
                }

                token.WriteTo(writer);
            }
            catch (Exception e)
            {
                throw new CryptoProviderEncryptFailedException(ProviderName, e);
            }
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.Null) return null;

            try
            {
                var encryptedFields = (JObject) JToken.ReadFrom(reader);
                var alg = encryptedFields.SelectToken("alg");
                var kid = encryptedFields.SelectToken("kid");
                var cipherText = encryptedFields.SelectToken("ciphertext");
                var iv = encryptedFields.SelectToken("iv");
                var signature = encryptedFields.SelectToken("sig");

                if (!CryptoProviders.TryGetValue(ProviderName, out var cryptoProvider))
                {
                    throw new CryptoProviderNotFoundException(ProviderName);
                }

                var cipherBytes = Convert.FromBase64String(cipherText.Value<string>());
                byte[] ivBytes = null;
                if (iv != null)
                {
                    ivBytes = Convert.FromBase64String(iv.Value<string>());
                }

                if (signature != null && ivBytes != null)
                {
                    //sig = BASE64(HMAC256(alg + BASE64(iv) + BASE64(ciphertext)))
                    var kidBytes = Encoding.UTF8.GetBytes(kid.Value<string>());
                    var algBytes = Encoding.UTF8.GetBytes(alg.Value<string>());

                    var buffer = new byte[kidBytes.Length + algBytes.Length + ivBytes.Length + cipherBytes.Length];
                    Buffer.BlockCopy(kidBytes, 0, buffer, 0, kidBytes.Length);
                    Buffer.BlockCopy(algBytes, 0, buffer, kidBytes.Length, algBytes.Length);
                    Buffer.BlockCopy(ivBytes, 0, buffer, kidBytes.Length + algBytes.Length, ivBytes.Length);
                    Buffer.BlockCopy(cipherBytes, 0, buffer, kidBytes.Length + algBytes.Length + ivBytes.Length,
                        cipherBytes.Length);

                    var sig = cryptoProvider.GetSignature(buffer);
                    if (signature.Value<string>() != Convert.ToBase64String(sig))
                    {
                        throw new CryptoProviderSigningFailedException(ProviderName);
                    }
                }

                byte[] decryptedPayload = null;
                decryptedPayload = cryptoProvider.PrivateKeyName == null
                    ? cryptoProvider.Decrypt(cipherBytes, ivBytes, kid.Value<string>())
                    : cryptoProvider.Decrypt(cipherBytes, ivBytes);

                return ConvertToType(Encoding.UTF8.GetString(decryptedPayload));
            }
            catch (CryptoProviderSigningFailedException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new CryptoProviderDecryptFailedException(ProviderName, e);
            }
        }

        public override bool CanConvert(Type objectType)
        {
            return true;
        }

        private object ConvertToType(string decryptedValue)
        {
            var typeCode = Type.GetTypeCode(TargetProperty.PropertyType);
            switch (typeCode)
            {
                case TypeCode.Boolean:
                    return JsonConvert.DeserializeObject<bool>(decryptedValue);
                case TypeCode.Byte:
                    return JsonConvert.DeserializeObject<byte>(decryptedValue);
                case TypeCode.Char:
                    return JsonConvert.DeserializeObject<char>(decryptedValue);
                case TypeCode.DateTime:
                    return JsonConvert.DeserializeObject<DateTime>(decryptedValue);
#if NET45
                case TypeCode.DBNull:
                    return null;
#endif
                case TypeCode.Decimal:
                    return JsonConvert.DeserializeObject<Decimal>(decryptedValue);
                case TypeCode.Double:
                    return JsonConvert.DeserializeObject<double>(decryptedValue);
                case TypeCode.Empty:
                    return null;
                case TypeCode.Int16:
                    return JsonConvert.DeserializeObject<short>(decryptedValue);
                case TypeCode.Int32:
                    return JsonConvert.DeserializeObject<int>(decryptedValue);
                case TypeCode.Int64:
                    return JsonConvert.DeserializeObject<long>(decryptedValue);
                case TypeCode.Object:
                    return JsonConvert.DeserializeObject(decryptedValue, TargetProperty.PropertyType);
                case TypeCode.SByte:
                    return JsonConvert.DeserializeObject<sbyte>(decryptedValue);
                case TypeCode.Single:
                    return JsonConvert.DeserializeObject<float>(decryptedValue);
                case TypeCode.String:
                    return JsonConvert.DeserializeObject<string>(decryptedValue);
                case TypeCode.UInt16:
                    return JsonConvert.DeserializeObject<ushort>(decryptedValue);
                case TypeCode.UInt32:
                    return JsonConvert.DeserializeObject<uint>(decryptedValue);
                case TypeCode.UInt64:
                    return JsonConvert.DeserializeObject<ulong>(decryptedValue);
            }
            return null;
        }
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
