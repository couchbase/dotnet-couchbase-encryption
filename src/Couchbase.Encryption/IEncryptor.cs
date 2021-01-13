using System;

namespace Couchbase.Encryption
{
    public interface IEncryptor
    {
        EncryptionResult Encrypt(byte[] plaintext);
    }
}
