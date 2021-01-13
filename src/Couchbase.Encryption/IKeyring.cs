namespace Couchbase.Encryption
{
    public interface IKeyring
    {
        IKey Get(string keyId);

        IKey GetOrThrow(string keyId);
    }
}
