using System;
using System.Reflection;

namespace Couchbase.Encryption.Attributes
{
    public static class MemberInfoExtensions
    {
        public static bool TryGetEncryptedFieldAttribute(this MemberInfo methodInfo, out EncryptedFieldAttribute attribute)
        {
            attribute = methodInfo.GetCustomAttribute<EncryptedFieldAttribute>();
            return attribute != null;
        }
    }
}
