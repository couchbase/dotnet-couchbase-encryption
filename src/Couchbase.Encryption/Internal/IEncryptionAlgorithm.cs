namespace Couchbase.Encryption.Internal
{
    public interface IEncryptionAlgorithm
    {
        string Algorithm { get; }
        byte[] Decrypt(byte[] key, byte[] cipherText, byte[] associatedData);
        byte[] Encrypt(byte[] key, byte[] plaintext, byte[] associatedData);
    }
}