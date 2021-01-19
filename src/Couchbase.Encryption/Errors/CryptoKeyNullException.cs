using Couchbase.Encryption.Attributes;

namespace Couchbase.Encryption.Errors
{
    /// <summary>
    /// The KeyName of the <see cref="EncryptedFieldAttribute"/> was null or empty.
    /// </summary>
    public sealed class CryptoKeyNullException : CouchbaseException
    {
    }
}
