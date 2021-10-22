using System.Security.Cryptography;
using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption.Legacy
{
    public class LegacyRsaCipher : IEncryptionAlgorithm
    {
        private const bool UseOaepPadding = true;

        public int KeySize { get; set; } = 2048;

        public string Algorithm { get; } = "RSA-2048-OAEP-SHA1";

        public byte[] Decrypt(byte[] key, byte[] cipherText, byte[] associatedData)
        {
            using var rsa = new RSACryptoServiceProvider(KeySize);
            var privateKey = key.FromBytes(false);
            rsa.ImportParameters(privateKey);

            return rsa.Decrypt(cipherText, UseOaepPadding);
        }

        public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] associatedData)
        {
            throw new System.NotImplementedException();
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
