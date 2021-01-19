namespace Couchbase.Encryption.Internal.Legacy
{
    /// <summary>
    /// Thrown if key size does not match the size of the key that the algorithm expects.
    /// </summary>
    public class CryptoProviderKeySizeException : CryptoProviderException
    {
        public const string MessageFormat =
            "The key found does not match the size of the key that the algorithm expects for the alias:" +
                " {0}. Expected key size was {1} and configured key is {2}";

        public CryptoProviderKeySizeException(string providerName, int expectedSize, int actualSize)
            : base(string.Format(MessageFormat, providerName, expectedSize, actualSize))
        {
        }
    }
}
