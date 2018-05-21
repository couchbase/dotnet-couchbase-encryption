using System;

namespace Couchbase.Extensions.Encryption
{
    public class CryptoProviderNotFoundException : Exception
    {
        public CryptoProviderNotFoundException(string providerName)
        {
            ProviderName = providerName;
        }

        public CryptoProviderNotFoundException(string message, string providerName)
            : base(message)
        {
            ProviderName = providerName;
        }

        public CryptoProviderNotFoundException(string message, string providerName, Exception innerException)
            : base(message, innerException)
        {
            ProviderName = providerName;
        }

        public string ProviderName { get; set; }
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
