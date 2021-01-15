using System;
using System.Collections.Generic;
using System.Linq;

namespace Couchbase.Encryption
{
    public class Keyring : IKeyring
    {
        private readonly IDictionary<string, IKey> _keys;

        public Keyring(IEnumerable<IKey> keys)
        {
            _keys = keys.ToDictionary(x => x.Id, y => y);
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
