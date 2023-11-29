using System;

namespace Couchbase.Encryption.Legacy
{
    internal class LegacyHmac256Encryptor : IEncryptor
    {
        private readonly LegacyHmac256Cipher _cipher;
        private readonly IKeyring _keyring;
        private readonly string _signingKeyName;

        public LegacyHmac256Encryptor(LegacyHmac256Cipher cipher, IKeyring keyring, string signingKeyName)
        {
            _cipher = cipher;
            _keyring = keyring;
            _signingKeyName = signingKeyName;
        }

        public EncryptionResult Encrypt(byte[] plaintext)
        {
            var key = _keyring.GetOrThrow(_signingKeyName);
            return new EncryptionResult
            {
                Alg = _cipher.Algorithm,
                Ciphertext = Convert.ToBase64String(_cipher.Encrypt(key.Bytes, plaintext, Array.Empty<byte>())),
                Kid = _signingKeyName
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
