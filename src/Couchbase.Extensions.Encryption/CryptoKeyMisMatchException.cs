using System;

namespace Couchbase.Extensions.Encryption
{
    /// <summary>
    /// Thrown when there is a mismatch between the keyname configured in the <see cref="ICryptoProvider"/> and the <see cref="IKeystoreProvider"/>/>
    /// </summary>
    public class CryptoKeyMismatchException : Exception
    {
        public CryptoKeyMismatchException(string expected, string publicKeyName, string privateKeyName) :
            this(string.Format(FormatMessage, expected, publicKeyName, privateKeyName))
        {
        }

        public CryptoKeyMismatchException(string message)
            : base(message)
        {
        }

        public CryptoKeyMismatchException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        public const string FormatMessage =
            "The the crypto provider keyname must match the key defined in the keyname store. " +
            "Expected '{0}' but found '{1}' and '{2}'.";
    }
}
