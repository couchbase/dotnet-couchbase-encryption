using System.Collections.Generic;
using System.Linq;
using Couchbase.Configuration.Client;
using Newtonsoft.Json;

namespace Couchbase.Extensions.Encryption
{
    public static class ClientConfigurationExtensions
    {
        public static void EnableFieldEncryption(this ClientConfiguration config, string providerName, ICryptoProvider provider)
        {
            EnableFieldEncryption(config, new KeyValuePair<string, ICryptoProvider>(providerName, provider));
        }

        public static void EnableFieldEncryption(this ClientConfiguration config,
            params KeyValuePair<string, ICryptoProvider>[] providers)
        {
            config.Serializer = () =>
            {
                return new EncryptedFieldSerializer(
                    new JsonSerializerSettings
                    {
                        ContractResolver =
                            new EncryptedFieldContractResolver(providers.ToDictionary(x => x.Key, x => x.Value))
                    },
                    new JsonSerializerSettings
                    {
                        ContractResolver =
                            new EncryptedFieldContractResolver(providers.ToDictionary(x => x.Key, x => x.Value))
                    });
            };
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
