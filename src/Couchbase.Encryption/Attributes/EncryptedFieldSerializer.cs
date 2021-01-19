using Couchbase.Core.IO.Serializers;
using Newtonsoft.Json;

namespace Couchbase.Encryption.Attributes
{
    public class EncryptedFieldSerializer : DefaultSerializer
    {
        public EncryptedFieldSerializer()
        {
        }

        public EncryptedFieldSerializer(JsonSerializerSettings deserializationSettings, JsonSerializerSettings serializerSettings) : base(deserializationSettings, serializerSettings)
        {
        }
    }
}
