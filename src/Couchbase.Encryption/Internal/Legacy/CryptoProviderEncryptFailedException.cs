using System;

namespace Couchbase.Encryption.Internal.Legacy
{
    /// <summary>
    /// Thrown if an error occurs during encryption.
    /// </summary>
    public class CryptoProviderEncryptFailedException : CryptoProviderException
    {
        public const string MessageFormat =
            "The encryption of the field failed for the alias: {0}";

        public CryptoProviderEncryptFailedException(string providerName)
            : base(string.Format(MessageFormat, providerName))
        {
        }

        public CryptoProviderEncryptFailedException(string providerName, Exception innerException)
            : base(string.Format(MessageFormat, providerName), innerException)
        {
        }
    }
}
