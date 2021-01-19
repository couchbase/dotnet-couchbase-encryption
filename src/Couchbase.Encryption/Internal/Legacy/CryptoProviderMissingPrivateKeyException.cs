namespace Couchbase.Encryption.Internal.Legacy
{
    /// <summary>
    /// Thrown when the PrivateKeyName field has not been set in the crypto provider configuration or is null or an empty string.
    /// </summary>
    public class CryptoProviderMissingPrivateKeyException : CryptoProviderException
    {
        public const string MessageFormat =
            "Cryptographic providers require a non-null, empty private key identifier (kid) be configured for the alias: {0}";

        public CryptoProviderMissingPrivateKeyException(string providerName)
            : base(string.Format(MessageFormat, providerName))
        {
        }
    }
}
