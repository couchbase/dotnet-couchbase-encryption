﻿using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption
{
    internal class Decryptor : IDecryptor
    {
        private readonly IEncryptionAlgorithm _cipher;
        private readonly IKeyring _keyring;

        public Decryptor(IEncryptionAlgorithm cipher, IKeyring keyring)
        {
            _cipher = cipher;
            _keyring = keyring;
        }

        internal byte[] AssociatedData { get; set; }

        public string Algorithm => _cipher.Algorithm;

        public byte[] Decrypt(EncryptionResult encrypted)
        {
            var key = _keyring.GetOrThrow(encrypted.Kid);
            var cipherBytes = System.Convert.FromBase64String(encrypted.Ciphertext);
            var plainBytes = _cipher.Decrypt(key.Bytes, cipherBytes, AssociatedData);
            return plainBytes;
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
