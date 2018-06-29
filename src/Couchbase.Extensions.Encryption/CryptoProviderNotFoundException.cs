using System;

namespace Couchbase.Extensions.Encryption
{
    /// <summary>
    /// Thrown when no crypto provider can be found for a given alias.
    /// </summary>
    public class CryptoProviderNotFoundException : Exception
    {
        public const string FormatMessage = "The cryptographic provider could not be found for the alias: {0}";

        public CryptoProviderNotFoundException(string providerName)
            : base(string.Format(FormatMessage, providerName))
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
