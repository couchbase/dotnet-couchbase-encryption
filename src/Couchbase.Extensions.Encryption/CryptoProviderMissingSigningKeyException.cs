namespace Couchbase.Extensions.Encryption
{
    /// <summary>
    /// Thrown when the SigningKeyName field has not been set in the crypto provider configuration or is null or and empty string. Required for symmetric algos.
    /// </summary>
    public  class CryptoProviderMissingSigningKeyException : CryptoProviderException
    {
        public const string MessageFormat =
            "Symmetric key cryptographic providers require a non-null, empty signing key be configured for the alias: {0}";

        public CryptoProviderMissingSigningKeyException(string providerName)
            : base(string.Format(MessageFormat, providerName))
        {
        }
    }
}
