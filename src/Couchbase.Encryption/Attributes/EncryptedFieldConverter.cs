using System;
using System.Reflection;
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
        private readonly string _keyName;

        public EncryptedFieldConverter(PropertyInfo propertyInfo, ICryptoManager cryptoManager, string keyName)
        {
            _propertyInfo = propertyInfo;
            _cryptoManager = cryptoManager;
            _keyName = keyName;
            SerializerSettings =
                new JsonSerializerSettings
                {
                    ContractResolver = new CamelCasePropertyNamesContractResolver()
                };
        }

        public JsonSerializerSettings SerializerSettings { get; set; }

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

            var encryptedResult = EncryptionResult.FromJObject((JObject) JToken.ReadFrom(reader));
            var plainText = _cryptoManager.Decrypt(encryptedResult);
            return ConvertToType(Encoding.UTF8.GetString(plainText));
        }

        public override bool CanConvert(Type objectType)
        {
            return true;
        }

        private object ConvertToType(string decryptedValue)
        {
            var typeCode = Type.GetTypeCode(_propertyInfo.PropertyType);
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
                    return JsonConvert.DeserializeObject(decryptedValue, _propertyInfo.PropertyType);
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
