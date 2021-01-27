namespace Couchbase.Encryption.IntegrationTests
{
    public static class FakeKeyGenerator
    {
        public static byte[] GetKey(int len)
        {
            var result = new byte[len];
            for (var i = 0; i < len; i++)
            {
                result[i] = (byte)i;
            }
            return result;
        }
    }
}