using System;

namespace Couchbase.Encryption.UnitTests
{
    public class FakeRandomNumberGenerator : IRandomNumberGenerator
    {
        private byte[] _bytes;

        public FakeRandomNumberGenerator(byte[] bytes)
        {
            _bytes =  bytes;
        }

        public void Fill(Span<byte> data)
        {
            var temp = new Span<byte>(_bytes);
            temp.CopyTo(data);
        }
    }
}
