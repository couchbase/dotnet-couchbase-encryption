using System;

namespace Couchbase.Encryption.UnitTests.Utils
{
    public static class StringExtensions
    {
        public static byte[] StringToByteArray(this string hex)
        {
            hex = hex.Replace(" ", "");
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return bytes;
        }
    }
}
