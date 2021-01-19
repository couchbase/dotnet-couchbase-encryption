using System;

namespace Couchbase.Encryption.Internal.Legacy
{
    [AttributeUsage(AttributeTargets.Property)]
    internal class EncryptedFieldAttribute : Attribute
    {
        public string Provider { get; set; }
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
