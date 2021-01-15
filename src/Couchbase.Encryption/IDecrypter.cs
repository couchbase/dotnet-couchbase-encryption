namespace Couchbase.Encryption
{
    public interface IDecrypter
    {
        string Algorithm { get; }

        byte[] Decrypt(EncryptionResult encrypted);
    }
}
