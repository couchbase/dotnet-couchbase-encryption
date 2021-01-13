using System;
using System.Collections.Generic;

namespace Couchbase.Encryption
{
    public class Keyring : IKeyring
    {
        private IDictionary<string, IKey> _keys;

        public Keyring(IDictionary<string, IKey> keys)
        {
            _keys = keys;
        }

        public IKey Get(string keyId)
        {
            return _keys[keyId];
        }

        public IKey GetOrThrow(string keyId)
        {
            return _keys[keyId];
        }
    }
}
