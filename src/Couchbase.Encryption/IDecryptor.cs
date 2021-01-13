namespace Couchbase.Encryption
{
    public interface IDecryptor
    {
        string Algorithm { get; }

        byte[] Decrypt(EncryptionResult encrypted);
    }
}
