using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace Couchbase.Encryption.Internal.Legacy.Stores
{
    internal class FileSystemKeyStore : IKeystoreProvider
    {
        public DataProtectionScope ProtectionScope { get; set; }

        public string StorePath { get; set; }

        public string GetKey(string keyname)
        {
            using (var stream = new FileStream(GetPath(keyname), FileMode.Open))
            {
                var encryptedBytes = new byte[stream.Length];
                stream.Read(encryptedBytes, 0, (int)stream.Length);

                var entropy = Encoding.ASCII.GetBytes(keyname);
                var decryptedBytes = ProtectedData.Unprotect(encryptedBytes, entropy, ProtectionScope);
                return Encoding.ASCII.GetString(decryptedBytes);
            }
        }

        public void StoreKey(string keyname, string key)
        {
            using (var stream = new FileStream(GetPath(keyname), FileMode.OpenOrCreate))
            {
                var userData = Encoding.ASCII.GetBytes(key);
                var entropy = Encoding.ASCII.GetBytes(keyname);
                var encryptedBytes = ProtectedData.Protect(userData, entropy, ProtectionScope);

                if (stream.CanWrite && encryptedBytes != null)
                {
                    stream.Write(encryptedBytes, 0, encryptedBytes.Length);
                }
            }
        }

        internal string GetPath(string storeName)
        {
            if (!storeName.Contains(".dat"))
            {
                storeName = string.Concat(storeName, ".dat");
            }
            return StorePath == null ? storeName : Path.Combine(StorePath, storeName);
        }
    }
}

#region [License information]
/* ************************************************************

 *    Copyright (c) 2018 Couchbase, Inc.
 *
 *    Use of this software is subject to the Couchbase Inc.
 *    Enterprise Subscription License Agreement which may be found
 *    at https://www.couchbase.com/ESLA-11132015.

 * ************************************************************/
#endregion