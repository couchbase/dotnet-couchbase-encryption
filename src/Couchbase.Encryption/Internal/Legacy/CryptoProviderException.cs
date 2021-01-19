using System;

namespace Couchbase.Encryption.Internal.Legacy
{
    /// <summary>
    /// Thrown for generic encryption failures and used as a base Exception class for other more specific exceptions.
    /// </summary>
    public class CryptoProviderException : Exception
    {
        public CryptoProviderException()
        {
        }

        public CryptoProviderException(string message)
            : base(message)
        {
        }

        public CryptoProviderException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
