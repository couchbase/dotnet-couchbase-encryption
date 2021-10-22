using System;
using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption
{
    internal class Encrypter : IEncrypter
    {
        private readonly IEncryptionAlgorithm _cipher;
        private readonly IKey _key;

        public Encrypter(IEncryptionAlgorithm cipher, IKey key)
        {
            _cipher = cipher;
            _key = key;
        }

        internal byte[] AssociatedData { get; set; } = Array.Empty<byte>();

        public EncryptionResult Encrypt(byte[] plaintext)
        {
            var encrypted = _cipher.Encrypt(_key.Bytes, plaintext, AssociatedData);
            return new EncryptionResult
            {
                Alg = _cipher.Algorithm,
                Ciphertext = Convert.ToBase64String(encrypted),
                Kid = _key.Id
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
