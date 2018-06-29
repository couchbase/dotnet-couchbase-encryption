namespace Couchbase.Extensions.Encryption
{
    /// <summary>
    /// Thrown when the PublicKeyName field has not been set in the crypto provider configuration or is null or an empty string.
    /// </summary>
    public class CryptoProviderMissingPublicKeyException : CryptoProviderException
    {
        public const string MessageFormat =
            "Cryptographic providers require a non-null, empty public key identifier (kid) be configured for the alias: {0}";

        public CryptoProviderMissingPublicKeyException(string providerName)
            : base(string.Format(MessageFormat, providerName))
        {
        }
    }
}
