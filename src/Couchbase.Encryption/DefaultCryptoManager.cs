using System;
using System.Collections.Generic;
using Couchbase.Encryption.Errors;

namespace Couchbase.Encryption
{
    public class DefaultCryptoManager : ICryptoManager
    {
        private readonly IDictionary<string, IEncrypter> _encrypters;
        private readonly IDictionary<string, IDecrypter> _decrypters;
        private readonly string _encryptedFieldNamePrefix;

        internal static string DefaultEncrypterAlias = "__DEFAULT__";
        private static string DefaultEncryptedFieldNamePrefix = "encrypted$";

        private DefaultCryptoManager(IDictionary<string, IEncrypter> encrypters, IDictionary<string, IDecrypter> decrypters, string encryptedFieldNamePrefix)
        {
            _encrypters = encrypters;
            _decrypters = decrypters;
            _encryptedFieldNamePrefix = encryptedFieldNamePrefix;
        }

        public sealed class CryptoBuilder
        {
            private readonly Dictionary<string, IEncrypter> _encrypters = new Dictionary<string, IEncrypter>();
            private readonly Dictionary<string, IDecrypter> _decrypters = new Dictionary<string, IDecrypter>();
            private string _encryptedNamePrefix = DefaultEncryptedFieldNamePrefix;

            public CryptoBuilder Encrypter(string alias, IEncrypter encrypter)
            {
                if (_encrypters.TryAdd(alias, encrypter)) return this;
                throw new InvalidOperationException($"Encrypter alias '{alias}' is already associated with {encrypter}");
            }

            public CryptoBuilder Decrypter(IDecrypter decrypter)
            {
                if (_decrypters.TryAdd(decrypter.Algorithm, decrypter)) return this;
                throw new InvalidOperationException($"Encrypter alias '{decrypter.Algorithm}' is already associated with {decrypter}");
            }

            public CryptoBuilder DefaultEncryptor(IEncrypter encrypter)
            {
                return Encrypter(DefaultEncrypterAlias, encrypter);
            }

            public CryptoBuilder EncryptedFieldNamePrefix(string encryptedFieldNamePrefix)
            {
                if(string.IsNullOrWhiteSpace(encryptedFieldNamePrefix)) throw new ArgumentNullException(nameof(encryptedFieldNamePrefix));
                _encryptedNamePrefix = encryptedFieldNamePrefix;
                return this;
            }

            public DefaultCryptoManager Build()
            {
                return new DefaultCryptoManager(_encrypters, _decrypters, _encryptedNamePrefix);
            }
        }

        public static CryptoBuilder Builder()
        {
            return new CryptoBuilder();
        }

        public EncryptionResult Encrypt(byte[] plainText, string encrypterAlias = null)
        {
            var alias = encrypterAlias ?? DefaultEncrypterAlias;
            if(_encrypters.TryGetValue(alias, out var encrypter))
            {
                return encrypter.Encrypt(plainText);
            }

            throw EncrypterNotFoundException.Create(encrypterAlias);
        }

        public byte[] Decrypt(EncryptionResult encrypted)
        {
            if (_decrypters.TryGetValue(encrypted.Alg, out var decrypter))
            {
                return decrypter.Decrypt(encrypted);
            }

            throw DecrypterNotFoundException.Create(encrypted.Kid);
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
