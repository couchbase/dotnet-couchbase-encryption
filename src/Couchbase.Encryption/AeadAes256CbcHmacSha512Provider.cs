using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption
{
    public class AeadAes256CbcHmacSha512Provider
    {
        private readonly IEncryptionAlgorithm _cipher;
        private readonly IKeyring _keyring;

        private static readonly byte[] NoAssociatedData = System.Array.Empty<byte>();

        public AeadAes256CbcHmacSha512Provider(IEncryptionAlgorithm cipher, IKeyring keyring)
        {
            _cipher = cipher;
            _keyring = keyring;
        }

        public IEncryptor Encryptor(string keyId)
        {
            return new Encryptor(_cipher, _keyring.Get(keyId))
            {
                AssociatedData = NoAssociatedData
            };
        }

        public IDecryptor Decryptor()
        {
            return new Decryptor(_cipher, _keyring)
            {
                AssociatedData = NoAssociatedData
            };
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
