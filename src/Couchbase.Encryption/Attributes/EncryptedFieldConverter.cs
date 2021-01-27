using System;
using System.Reflection;
using System.Security.Policy;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace Couchbase.Encryption.Attributes
{
    public class EncryptedFieldConverter : JsonConverter
    {
        private readonly PropertyInfo _propertyInfo;
        private readonly ICryptoManager _cryptoManager;
        private readonly string _legacySigningKeyName;
        private static string NonLegacyAlgorithim = "AEAD_AES_256_CBC_HMAC_SHA512";

        public EncryptedFieldConverter(PropertyInfo propertyInfo, ICryptoManager cryptoManager, string legacySigningKeyName)
        {
            _propertyInfo = propertyInfo;
            _cryptoManager = cryptoManager;
            _legacySigningKeyName = legacySigningKeyName;
            SerializerSettings =
                new JsonSerializerSettings
                {
                    ContractResolver = new CamelCasePropertyNamesContractResolver()
                };
        }

        public JsonSerializerSettings SerializerSettings { get; set; }

        public override bool CanRead => true;

        public override bool CanWrite => true;

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var rawJson = JsonConvert.SerializeObject(value, SerializerSettings);
            var plainText = Encoding.UTF8.GetBytes(rawJson);

            var encryptionResult = _cryptoManager.Encrypt(plainText);
            var token = encryptionResult.ToJObject();

            token.WriteTo(writer);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.Null) return null;

            var encryptedJObject = (JObject) JToken.ReadFrom(reader);
            if (encryptedJObject.Value<string>("alg") != NonLegacyAlgorithim)
            {
                //decrypt using the legacy algorithm - will upgrade on write back
                var legacyPlainText = encryptedJObject.Decrypt(_legacySigningKeyName, _cryptoManager);
                return ConvertToType(Encoding.UTF8.GetString(legacyPlainText));
            }

            var encryptedResult = EncryptionResult.FromJObject(encryptedJObject);
            var plainText = _cryptoManager.Decrypt(encryptedResult);
            return ConvertToType(Encoding.UTF8.GetString(plainText));
        }

        public override bool CanConvert(Type objectType)
        {
            var typeCode = Type.GetTypeCode(_propertyInfo.PropertyType);
            return typeCode switch
            {
                TypeCode.Boolean => true,
                TypeCode.Byte => true,
                TypeCode.Char => true,
                TypeCode.DateTime => true,
                TypeCode.Decimal => true,
                TypeCode.Double => true,
                TypeCode.Empty => true,
                TypeCode.Int16 => true,
                TypeCode.Int32 => true,
                TypeCode.Int64 => true,
                TypeCode.Object => true,
                TypeCode.SByte => true,
                TypeCode.Single => true,
                TypeCode.String => true,
                TypeCode.UInt16 => true,
                TypeCode.UInt32 => true,
                TypeCode.UInt64 => true,
                _ => false
            };
        }

        private object ConvertToType(string decryptedValue)
        {
            var typeCode = Type.GetTypeCode(_propertyInfo.PropertyType);
            return typeCode switch
            {
                TypeCode.Boolean => JsonConvert.DeserializeObject<bool>(decryptedValue),
                TypeCode.Byte => JsonConvert.DeserializeObject<byte>(decryptedValue),
                TypeCode.Char => JsonConvert.DeserializeObject<char>(decryptedValue),
                TypeCode.DateTime => JsonConvert.DeserializeObject<DateTime>(decryptedValue),
                TypeCode.Decimal => JsonConvert.DeserializeObject<Decimal>(decryptedValue),
                TypeCode.Double => JsonConvert.DeserializeObject<double>(decryptedValue),
                TypeCode.Empty => null,
                TypeCode.Int16 => JsonConvert.DeserializeObject<short>(decryptedValue),
                TypeCode.Int32 => JsonConvert.DeserializeObject<int>(decryptedValue),
                TypeCode.Int64 => JsonConvert.DeserializeObject<long>(decryptedValue),
                TypeCode.Object => JsonConvert.DeserializeObject(decryptedValue, _propertyInfo.PropertyType),
                TypeCode.SByte => JsonConvert.DeserializeObject<sbyte>(decryptedValue),
                TypeCode.Single => JsonConvert.DeserializeObject<float>(decryptedValue),
                TypeCode.String => JsonConvert.DeserializeObject<string>(decryptedValue),
                TypeCode.UInt16 => JsonConvert.DeserializeObject<ushort>(decryptedValue),
                TypeCode.UInt32 => JsonConvert.DeserializeObject<uint>(decryptedValue),
                TypeCode.UInt64 => JsonConvert.DeserializeObject<ulong>(decryptedValue),
                _ => throw new NotSupportedException($"The decrypted value type '{typeCode}` is a non-supported type.")
            };
        }
    }
}
