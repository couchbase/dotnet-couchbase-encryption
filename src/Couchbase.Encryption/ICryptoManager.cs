using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Couchbase.Encryption
{
    public interface ICryptoManager
    {
        EncryptionResult Encrypt(byte[] plaintext, string encryptorAlias);

        byte[] Decrypt(EncryptionResult encrypted);

        string Mangle(string fieldName);

        string Demangle(string fieldName);

        bool IsMangled(string fieldName);
    }
}
