namespace Couchbase.Encryption
{
    public interface ICryptoManager
    {
        EncryptionResult Encrypt(byte[] plainText, string encrypterAlias);

        byte[] Decrypt(EncryptionResult encrypted);

        string Mangle(string fieldName);

        string Demangle(string fieldName);

        bool IsMangled(string fieldName);
    }
}
