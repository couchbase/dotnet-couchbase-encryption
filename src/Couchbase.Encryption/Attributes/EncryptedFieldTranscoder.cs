using Couchbase.Core.IO.Serializers;
using Couchbase.Core.IO.Transcoders;
using Newtonsoft.Json;

namespace Couchbase.Encryption.Attributes
{
    public class EncryptedFieldTranscoder : JsonTranscoder
    {
        private readonly ICryptoManager _cryptoManager;

        public EncryptedFieldTranscoder(ICryptoManager cryptoManager) : this(cryptoManager, new EncryptedFieldSerializer(
            new JsonSerializerSettings
            {
                ContractResolver = new EncryptedFieldContractResolver(cryptoManager)
            }, new JsonSerializerSettings
            {
                ContractResolver = new EncryptedFieldContractResolver(cryptoManager)
            }))
        {
        }

        public EncryptedFieldTranscoder(ICryptoManager cryptoManager, ITypeSerializer serializer) : base(serializer)
        {
            _cryptoManager = cryptoManager;
        }

        public EncryptedFieldTranscoder(ICryptoManager cryptoManager, JsonSerializerSettings deserializerSettings,
            JsonSerializerSettings serializerSettings) : base(
            new EncryptedFieldSerializer(deserializerSettings, serializerSettings))
        {
            _cryptoManager = cryptoManager;
        }
    }
}
