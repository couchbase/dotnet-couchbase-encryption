using System;
using System.Security.Cryptography;

namespace Couchbase.Encryption
{
    public class DefaultRandomNumberGenerator : IRandomNumberGenerator
    {
        public void Fill(Span<byte> data)
        {
            RandomNumberGenerator.Fill(data);
        }
    }
}
