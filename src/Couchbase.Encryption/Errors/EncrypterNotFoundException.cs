using System;
using System.Security.Cryptography;

namespace Couchbase.Encryption.Errors
{
    public class EncrypterNotFoundException : CryptographicException
    {
        public EncrypterNotFoundException(string alias, string message) : base(message)
        {
            Alias = alias;
        }

        public string Alias { get; }

        public static EncrypterNotFoundException Create(string alias)
        {
            return new EncrypterNotFoundException(alias,
                DefaultCryptoManager.DefaultEncrypterAlias.Equals(alias, StringComparison.InvariantCultureIgnoreCase)
                    ? "No default encrypter was registered. Please specify an encrypter or register a default encrypter."
                    : $"Missing encrypter for alias '{alias}'.");
        }
    }
}
