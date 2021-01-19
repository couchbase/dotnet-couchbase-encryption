using System;

namespace Couchbase.Encryption.Errors
{
    /// <summary>
    /// Thrown if the cipherText and associated data cannot be authenticated.
    /// </summary>
    public sealed class InvalidCiphertextException : CouchbaseException
    {
        public InvalidCiphertextException(string message) : base(message)
        {
        }

        public InvalidCiphertextException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
