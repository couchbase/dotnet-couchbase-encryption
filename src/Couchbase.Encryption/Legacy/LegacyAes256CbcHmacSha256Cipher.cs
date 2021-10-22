using System;
using System.IO;
using System.Security.Cryptography;
using Couchbase.Encryption.Internal;

namespace Couchbase.Encryption.Legacy
{
    internal class LegacyAes256CbcHmacSha256Cipher : IEncryptionAlgorithm
    {
        public string Algorithm => "AES-256-CBC-HMAC-SHA256";

        public byte[] Decrypt(byte[] key, byte[] cipherText, byte[] associatedData)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = associatedData;
            aes.Mode = CipherMode.CBC;

            var decrypter = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(cipherText);
            using var cs = new CryptoStream(ms, decrypter, CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            var value = sr.ReadToEnd();
            return System.Text.Encoding.UTF8.GetBytes(value);
        }

        public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] associatedData)
        {
            throw new NotImplementedException();
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
