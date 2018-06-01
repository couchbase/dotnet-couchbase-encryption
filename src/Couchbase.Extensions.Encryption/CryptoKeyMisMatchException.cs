using System;

namespace Couchbase.Extensions.Encryption
{
    /// <summary>
    /// Thrown when there is a mismatch between the keyname configured in the <see cref="ICryptoProvider"/> and the <see cref="IKeystoreProvider"/>/>
    /// </summary>
    public class CryptoKeyMisMatchException : Exception
    {
        public CryptoKeyMisMatchException(string expected, string publicKeyName, string privateKeyName) :
            this(string.Format(FormatMessage, expected, publicKeyName, privateKeyName))
        {
        }

        public CryptoKeyMisMatchException(string message)
            : base(message)
        {
        }

        public CryptoKeyMisMatchException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        public const string FormatMessage =
            "The the crypto provider keyname must match the key defined in the keyname store. " +
            "Expected '{0}' but found '{1}' and '{2}'.";
    }
}
