using Couchbase.Configuration.Client;
using Microsoft.Extensions.Configuration;

namespace Couchbase.Extensions.Encryption.IntegrationTests
{
    public static class TestConfiguration
    {
        public static ICouchbaseClientDefinition GetConfiguration()
        {
            var builder = new ConfigurationBuilder();
            builder.AddJsonFile("configuration.json");

            var configurationSection = builder.Build().GetSection("Couchbase");
            var definition = new CouchbaseClientDefinition();
            configurationSection.Bind(definition);

            return definition;
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