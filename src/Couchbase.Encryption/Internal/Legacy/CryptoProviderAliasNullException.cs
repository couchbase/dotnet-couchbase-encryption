
namespace Couchbase.Encryption.Internal.Legacy
{
    /// <summary>
    /// The <see cref="EncryptedFieldAttribute"/> has no associated alias or is null or and empty string.
    /// </summary
    public class CryptoProviderAliasNullException : CryptoProviderException
    {
        public const string MessageFormat = "Cryptographic providers require a non-null, empty alias be configured";

        public CryptoProviderAliasNullException()
            : base(MessageFormat)
        {
        }
    }
}
