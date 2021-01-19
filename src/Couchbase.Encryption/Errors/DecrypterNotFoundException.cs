namespace Couchbase.Encryption.Errors
{
    public sealed class DecrypterNotFoundException : CouchbaseException
    {
        public DecrypterNotFoundException(string algorithm, string message) : base(message)
        {
            Algorithm = algorithm;
        }

        public string Algorithm { get; }

        public static DecrypterNotFoundException Create(string algorithm)
        {
            return new DecrypterNotFoundException(algorithm, $"Missing decrypter for algorithm '{algorithm}'.");
        }
    }
}
