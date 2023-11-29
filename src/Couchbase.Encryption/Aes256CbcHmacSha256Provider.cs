using Couchbase.Encryption.Internal;
using Couchbase.Encryption.Legacy;

namespace Couchbase.Encryption
{
    public sealed class Aes256CbcHmacSha256Provider
    {
        private readonly IKeyring _keyring;
        private readonly IEncryptionAlgorithm _cipher;

        public Aes256CbcHmacSha256Provider(IKeyring keyring, IEncryptionAlgorithm cipher)
        {
            _keyring = keyring;
            _cipher = cipher;
        }

        public IDecryptor Decryptor()
        {
            return new LegacyAesDecryptor(_keyring, _cipher);
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
