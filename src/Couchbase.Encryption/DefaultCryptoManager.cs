using System;
using System.Collections.Generic;
using Couchbase.Encryption.Errors;
using Couchbase.Encryption.Legacy;

namespace Couchbase.Encryption
{
    public class DefaultCryptoManager : ICryptoManager
    {
        private readonly IDictionary<string, IEncryptor> _encryptors;
        private readonly IDictionary<string, IDecryptor> _decryptors;
        private readonly string _encryptedFieldNamePrefix;

        internal static readonly string DefaultEncryptorAlias = "__DEFAULT__";
        private const string DefaultEncryptedFieldNamePrefix = "encrypted$";

        private DefaultCryptoManager(IDictionary<string, IEncryptor> encryptors, IDictionary<string, IDecryptor> decryptors, string encryptedFieldNamePrefix)
        {
            _encryptors = encryptors;
            _decryptors = decryptors;
            _encryptedFieldNamePrefix = encryptedFieldNamePrefix;
        }

        public sealed class CryptoBuilder
        {
            private readonly Dictionary<string, IEncryptor> _encryptors = new();
            private readonly Dictionary<string, IDecryptor> _decryptors = new();
            private string _encryptedNamePrefix = DefaultEncryptedFieldNamePrefix;

            public CryptoBuilder Encryptor(string alias, IEncryptor encryptor)
            {
                if (_encryptors.TryAdd(alias, encryptor)) return this;
                throw new InvalidOperationException($"Encryptor alias '{alias}' is already associated with {encryptor}");
            }

            public CryptoBuilder Decryptor(IDecryptor decryptor)
            {
                if (_decryptors.TryAdd(decryptor.Algorithm, decryptor)) return this;
                throw new InvalidOperationException($"Decryptor alias '{decryptor.Algorithm}' is already associated with {decryptor}");
            }

            public CryptoBuilder DefaultEncryptor(IEncryptor encryptor)
            {
                return Encryptor(DefaultEncryptorAlias, encryptor);
            }

            public CryptoBuilder EncryptedFieldNamePrefix(string encryptedFieldNamePrefix)
            {
                if(string.IsNullOrWhiteSpace(encryptedFieldNamePrefix)) throw new ArgumentNullException(nameof(encryptedFieldNamePrefix));
                _encryptedNamePrefix = encryptedFieldNamePrefix;
                return this;
            }

            public CryptoBuilder LegacyAesDecryptors(Keyring keyring, string signingKeyName)
            {
                var legacyAesDecryptor = new LegacyAesDecryptor(keyring, new LegacyAes256CbcHmacSha256Cipher());
                var legacyHmacEncryptor = new LegacyHmac256Encryptor(new LegacyHmac256Cipher(), keyring, signingKeyName);
                if (_decryptors.TryAdd(legacyAesDecryptor.Algorithm, legacyAesDecryptor) && _encryptors.TryAdd(signingKeyName, legacyHmacEncryptor)) return this;

                throw new InvalidOperationException($"Decryptor algorithm '{legacyAesDecryptor.Algorithm}' is already associated with {legacyAesDecryptor.Algorithm}");
            }

            public CryptoBuilder LegacyRsaDecryptor(Keyring keyring, string signingKeyName)
            {
                var legacyRsaDecryptor = new LegacyRsaDecryptor(keyring, new LegacyRsaCipher());
                if (_decryptors.TryAdd(legacyRsaDecryptor.Algorithm, legacyRsaDecryptor)) return this;

                throw new InvalidOperationException($"Decryptor algorithm '{legacyRsaDecryptor.Algorithm}' is already associated with {legacyRsaDecryptor.Algorithm}");
            }

            public DefaultCryptoManager Build()
            {
                return new DefaultCryptoManager(_encryptors, _decryptors, _encryptedNamePrefix);
            }
        }

        public static CryptoBuilder Builder()
        {
            return new CryptoBuilder();
        }

        public EncryptionResult Encrypt(byte[] plainText, string encryptorAlias = null)
        {
            var alias = encryptorAlias ?? DefaultEncryptorAlias;
            if(_encryptors.TryGetValue(alias, out var encryptor))
            {
                return encryptor.Encrypt(plainText);
            }

            throw EncryptorNotFoundException.Create(encryptorAlias);
        }

        public byte[] Decrypt(EncryptionResult encrypted)
        {
            if (_decryptors.TryGetValue(encrypted.Alg, out var decryptor))
            {
                return decryptor.Decrypt(encrypted);
            }

            throw DecryptorNotFoundException.Create(encrypted.Kid);
        }

        public string Mangle(string fieldName)
        {
            return string.Concat(_encryptedFieldNamePrefix, fieldName);
        }

        public string Demangle(string fieldName)
        {
            return fieldName.Replace(_encryptedFieldNamePrefix, "", StringComparison.InvariantCultureIgnoreCase);
        }

        public bool IsMangled(string fieldName)
        {
            return fieldName.StartsWith(_encryptedFieldNamePrefix);
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
