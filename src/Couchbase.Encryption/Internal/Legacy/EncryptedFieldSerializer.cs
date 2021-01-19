using Couchbase.Core.IO.Serializers;
using Newtonsoft.Json;

namespace Couchbase.Encryption.Internal.Legacy
{
    internal class EncryptedFieldSerializer : DefaultSerializer
    {
        public EncryptedFieldSerializer()
        {
        }

        public EncryptedFieldSerializer(JsonSerializerSettings deserializationSettings, JsonSerializerSettings serializerSettings) : base(deserializationSettings, serializerSettings)
        {
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
