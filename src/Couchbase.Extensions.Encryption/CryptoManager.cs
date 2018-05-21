using System.Collections.Concurrent;

namespace Couchbase.Extensions.Encryption
{
    public static class CryptoManager
    {
        private static readonly ConcurrentDictionary<string, ICryptoProvider> Providers = new ConcurrentDictionary<string, ICryptoProvider>();

        public static void Register(string providerName, ICryptoProvider provider)
        {
            //consider throwing CryptoProviderAlreadyExistsException?
            Providers.TryAdd(providerName, provider);
        }

        public static void UnRegister(string providerName)
        {
            //consider throwing CryptoProviderNotFoundException
            Providers.TryRemove(providerName, out var provider);
        }

        public static ICryptoProvider GetCryptoProvider(string providerName)
        {
            if (Providers.TryGetValue(providerName, out var provider))
            {
                return provider;
            }

            throw new CryptoProviderNotFoundException(providerName);
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
