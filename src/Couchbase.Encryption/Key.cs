namespace Couchbase.Encryption
{
    public class Key : IKey
    {
        public Key(string id, byte[] bytes)
        {
            Id = id;
            Bytes = bytes;
        }
        public byte[] Bytes { get; }
        public string Id { get; }
    }
}
