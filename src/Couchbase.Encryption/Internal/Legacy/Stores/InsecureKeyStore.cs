using System.Collections.Generic;
using System.Linq;

namespace Couchbase.Encryption.Internal.Legacy.Stores
{
    internal class InsecureKeyStore : IKeystoreProvider
    {
        private readonly Dictionary<string, string> _keys = new Dictionary<string, string>();

        public InsecureKeyStore()
        {
        }

        public InsecureKeyStore(string keyname, string key)
        {
            _keys.Add(keyname, key);
        }

        public InsecureKeyStore(params KeyValuePair<string, string>[] keys)
        {
            _keys = keys.ToDictionary(x=>x.Key, x=>x.Value);
        }

        public string GetKey(string keyname)
        {
            return _keys[keyname];
        }

        public void StoreKey(string keyname, string key)
        {
            _keys[keyname] = key;
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
