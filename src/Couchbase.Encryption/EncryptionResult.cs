using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace Couchbase.Encryption
{
    public class EncryptionResult : IEquatable<EncryptionResult>
    {
        private string _json;
        private string _alg;
        private string _kid;
        private string _ciphertext;

        internal byte[] Iv { get; set; }

        public string Alg
        {
            get => _alg;
            set
            {
                _alg = value;
                _json = null;
            }
        }

        public string Kid
        {
            get => _kid;
            set
            {
                _kid = value;
                _json = null;
            }
        }

        public string Ciphertext
        {
            get => _ciphertext;
            set
            {
                _ciphertext = value;
                _json = null;
            }
        }

        public JObject ToJObject()
        {
            return new(
                new JProperty(EncryptionField.Algorithm, Alg),
                new JProperty(EncryptionField.KeyIdentifier, Kid),
                new JProperty(EncryptionField.CipherText, Ciphertext));
        }

        public static EncryptionResult FromJObject(JObject jObject)
        {
            return new()
            {
                Alg = jObject.SelectToken(EncryptionField.Algorithm).Value<string>(),
                Kid = jObject.SelectToken(EncryptionField.KeyIdentifier).Value<string>(),
                Ciphertext = jObject.SelectToken(EncryptionField.CipherText).Value<string>()
            };
        }

        public override string ToString()
        {
            return _json ??= JsonConvert.SerializeObject(this, new JsonSerializerSettings
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver()
            });
        }

        public bool Equals(EncryptionResult other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _json == other._json && _alg == other._alg && _kid == other._kid && _ciphertext == other._ciphertext;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((EncryptionResult) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (_json != null ? _json.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (_alg != null ? _alg.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (_kid != null ? _kid.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (_ciphertext != null ? _ciphertext.GetHashCode() : 0);
                return hashCode;
            }
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
