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

            if (member.TryGetEncryptedFieldAttribute(out var attribute))
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


/* ************************************************************
 *
 *    @author Couchbase <info@couchbase.com>
 *    @copyright 2021 Couchbase, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 * ************************************************************/
