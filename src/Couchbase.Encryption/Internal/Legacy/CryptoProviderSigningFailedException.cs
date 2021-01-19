namespace Couchbase.Encryption.Internal.Legacy
{
    /// <summary>
    /// Thrown if the authentication check fails on the decryption side.
    /// </summary>
    public class CryptoProviderSigningFailedException : CryptoProviderException
    {
        public const string MessageFormat =
            "The authentication failed while checking the signature of the message payload for the alias: {0}";

        public CryptoProviderSigningFailedException(string providerName)
            : base(string.Format(MessageFormat, providerName))
        {
        }
    }
}
