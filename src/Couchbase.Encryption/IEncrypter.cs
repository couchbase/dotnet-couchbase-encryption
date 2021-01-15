using System;

namespace Couchbase.Encryption
{
    public interface IEncrypter
    {
        EncryptionResult Encrypt(byte[] plaintext);
    }
}
