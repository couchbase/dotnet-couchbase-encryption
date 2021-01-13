using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Couchbase.Encryption
{
    public class DefaultCryptoManager : ICryptoManager
    {
        private readonly IDictionary<string, IEncryptor> _encryptors;
        private readonly IDictionary<string, IDecryptor> _decryptors;

        private static string DefaultEncrypterAlias = "__DEFAULT__";
        private static string DefaultEncryptedFieldNamePrefix = "encrypted$";

        private DefaultCryptoManager(IDictionary<string, IEncryptor> encryptors, IDictionary<string, IDecryptor> decryptors)
        {
            _encryptors = encryptors;
            _decryptors = decryptors;
        }

        public sealed class Builder
        {
            private readonly Dictionary<string, IEncryptor> _encryptors = new Dictionary<string, IEncryptor>();
            private readonly Dictionary<string, IDecryptor> _decryptors = new Dictionary<string, IDecryptor>();

            public Builder Encryptor(string alias, IEncryptor encryptor)
            {
                if (_encryptors.TryAdd(alias, encryptor)) return this;
                throw new InvalidOperationException($"Encryptor alias '{alias}' is already associated with {encryptor}");
            }

            public Builder Decryptor(IDecryptor decryptor)
            {
                if (_decryptors.TryAdd(decryptor.Algorithm, decryptor)) return this;
                throw new InvalidOperationException($"Encryptor alias '{decryptor.Algorithm}' is already associated with {decryptor}");
            }

            public DefaultCryptoManager Build()
            {
                return new DefaultCryptoManager(_encryptors, _decryptors);
            }
        }

        public EncryptionResult Encrypt(byte[] plaintext, string encryptorAlias)
        {
            throw new NotImplementedException();
        }

        public byte[] Decrypt(EncryptionResult encrypted)
        {
            throw new NotImplementedException();
        }

        public string Mangle(string fieldName)
        {
            throw new NotImplementedException();
        }

        public string Demangle(string fieldName)
        {
            throw new NotImplementedException();
        }

        public bool IsMangled(string fieldName)
        {
            throw new NotImplementedException();
        }
    }
}
