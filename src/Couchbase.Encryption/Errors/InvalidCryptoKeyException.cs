using System;
using System.Security.Cryptography;

namespace Couchbase.Encryption.Errors
{
    /// <summary>
    /// Thrown if the encryption key length is not 64 bytes.
    /// </summary>
    public sealed class InvalidCryptoKeyException : CryptographicException
    {
        public InvalidCryptoKeyException(string message) : base(message)
        {
        }

        public InvalidCryptoKeyException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
