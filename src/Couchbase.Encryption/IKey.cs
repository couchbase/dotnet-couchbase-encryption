namespace Couchbase.Encryption
{
    public interface IKey
    {
        byte[] Bytes { get; }

        string Id { get; }
    }
}
