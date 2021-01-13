namespace Couchbase.Encryption
{
    public class EncryptionResult
    {
        public string Alg { get; set; }

        public string Kid { get; set; }

        public string CipherText { get; set; }
    }
}
