using System;

namespace Couchbase.Encryption
{
    public interface IRandomNumberGenerator
    {
        void Fill(Span<byte> data);
    }
}
