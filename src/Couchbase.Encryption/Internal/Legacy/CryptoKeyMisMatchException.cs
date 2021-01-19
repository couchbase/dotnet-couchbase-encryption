namespace Couchbase.Encryption.Internal.Legacy
{
    /// <summary>
    /// Thrown when there is a mismatch between the keyname configured in the <see cref="ICryptoProvider"/> and the <see cref="IKeystoreProvider"/>/>
    /// </summary>
    public class CryptoKeyMismatchException : CryptoProviderException
    {
        public CryptoKeyMismatchException(string expected, string publicKeyName, string privateKeyName) :
            base(string.Format(FormatMessage, expected, publicKeyName, privateKeyName))
        {
        }

        public const string FormatMessage =
            "The the crypto provider keyname must match the key defined in the keyname store. " +
            "Expected '{0}' but found '{1}' and '{2}'.";
    }
}
