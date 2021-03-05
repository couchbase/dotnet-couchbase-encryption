using System.Reflection;
using Couchbase.Encryption.Errors;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Couchbase.Encryption.Attributes
{
    public class EncryptedFieldContractResolver : CamelCasePropertyNamesContractResolver
    {
        private readonly ICryptoManager _cryptoManager;

        public EncryptedFieldContractResolver(ICryptoManager cryptoManager)
        {
            _cryptoManager = cryptoManager;
        }

        protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
        {
            var result = base.CreateProperty(member, memberSerialization);

            if (member.TryGetEncryptedFieldAttribute(out var attribute))
            {
                if (attribute.KeyName == null)
                {
                    throw new CryptoKeyNullException();
                }

                var propertyInfo = member as PropertyInfo;
                result.PropertyName = _cryptoManager.Mangle(result.PropertyName);

                result.Converter = new EncryptedFieldConverter(propertyInfo, _cryptoManager, attribute.LegacySigningKeyName);
            }

            return result;
        }
    }
}
