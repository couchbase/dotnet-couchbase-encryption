using System;

namespace Couchbase.Extensions.Encryption
{
    /// <summary>
    /// Thrown if an error occurs during encryption.
    /// </summary>
    public class CryptoProviderDecryptFailedException : CryptoProviderException
    {
        public const string MessageFormat =
            "The decryption of the field failed for the alias: {0}";

        public CryptoProviderDecryptFailedException(string providerName)
            : base(string.Format(MessageFormat, providerName))
        {
        }

        public CryptoProviderDecryptFailedException(string providerName, Exception innerException)
            : base(string.Format(MessageFormat, providerName), innerException)
        {
        }
    }
}
