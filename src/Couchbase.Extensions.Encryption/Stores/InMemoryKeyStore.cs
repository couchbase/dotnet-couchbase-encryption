using System;
using System.Security.Cryptography;

namespace Couchbase.Extensions.Encryption.Stores
{
    public class InMemoryKeyStore : IKeystoreProvider
    {
        public DataProtectionScope ProtectionScope { get; set; }

        public string GetKey(string keyname)
        {
            throw new NotImplementedException();
        }

        public void StoreKey(string keyname, string key)
        {
            //ProtectedMemory is not part of .NET Core :(
            throw new NotImplementedException();
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
