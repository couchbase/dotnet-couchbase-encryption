using System;
using System.Reflection;

namespace Couchbase.Encryption.Internal.Legacy.Utils
{
    internal static class MemberInfoExtensions
    {
        public static bool GetEncryptedFieldAttribute(this MemberInfo methodInfo, out EncryptedFieldAttribute attribute)
        {
#if NETSTANDARD15
            attribute = methodInfo.GetCustomAttribute<EncryptedFieldAttribute>();
            return attribute != null;
#else
            if (Attribute.IsDefined(methodInfo, typeof(EncryptedFieldAttribute)))
            {
                attribute = (EncryptedFieldAttribute)Attribute.
                    GetCustomAttribute(methodInfo, typeof(EncryptedFieldAttribute));

                return true;
            }
            attribute = null;
            return false;
#endif
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
