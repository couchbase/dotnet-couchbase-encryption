using System;
using System.Reflection;

namespace Couchbase.Encryption.Attributes
{
    public static class MemberInfoExtensions
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
