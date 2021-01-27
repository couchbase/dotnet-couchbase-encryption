using System.Reflection;
using Couchbase.Encryption.Attributes;
using Couchbase.Encryption.Errors;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Couchbase.Encryption.Legacy
{
    public class LegacyEncryptedFieldContractResolver : CamelCasePropertyNamesContractResolver
    {
        private readonly ICryptoManager _cryptoManager;
        private readonly string _legacyFieldPrefix;
        private static string DefaultLegacyPrefix = "__crypt_";

        public LegacyEncryptedFieldContractResolver(ICryptoManager cryptoManager, string legacyFieldPrefix = null)
        {
            _cryptoManager = cryptoManager;
            _legacyFieldPrefix = legacyFieldPrefix ?? DefaultLegacyPrefix;
        }

        protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
        {
            var result = base.CreateProperty(member, memberSerialization);

            if (member.GetEncryptedFieldAttribute(out var attribute))
            {
                if (attribute.KeyName == null)
                {
                    throw new CryptoKeyNullException();
                }

                var propertyInfo = member as PropertyInfo;

                if (_legacyFieldPrefix == null)
                {
                    result.PropertyName = _cryptoManager.Mangle(result.PropertyName);
                }
                else
                {
                    result.PropertyName = _legacyFieldPrefix + result.PropertyName;
                }

                result.Converter = new EncryptedFieldConverter(propertyInfo, _cryptoManager, attribute.LegacySigningKeyName);
            }

            return result;
        }
    }
}
