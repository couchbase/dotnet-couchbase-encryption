using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Couchbase.Encryption.Internal
{
    public sealed class AeadAes256CbcHmacSha512Cipher
    {
        private static int IvLength = 16;
        private static int AuthTagLength = 32;

        private HMACSHA512 _hmacsha512;
        private AesCryptoServiceProvider _aesCryptoProvider;
        private IRandomNumberGenerator _randomNumberGenerator;

        public AeadAes256CbcHmacSha512Cipher() : this(new DefaultRandomNumberGenerator())
        {
        }

        public AeadAes256CbcHmacSha512Cipher(IRandomNumberGenerator randomNumberGenerator)
        {
            _randomNumberGenerator = randomNumberGenerator;
            _hmacsha512 = new HMACSHA512();
            _aesCryptoProvider = new AesCryptoServiceProvider
            {
                BlockSize = 128,
                KeySize = 256,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC
            };
        }

        public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] associatedData)
        {
            var macKey = new Span<byte>(key).Slice(0, 32);
            var encKey = new Span<byte>(key).Slice(32, 32);

            var enc = EncryptAesCbcPkcs7(encKey, plaintext);
            var associatedDataLengthInBits = BitConverter.GetBytes(associatedData.Length * 8L);
            var computedMac = HmacSha512(macKey.ToArray(), associatedData, enc, associatedDataLengthInBits);
            var authTag = new Span<byte>(computedMac).Slice(0, AuthTagLength).ToArray();

            return Concat(enc, authTag);
        }

        private byte[] EncryptAesCbcPkcs7(Span<byte> key, byte[] plaintext)
        {
            var iv = new Span<byte>(new byte[IvLength]);
            _randomNumberGenerator.Fill(iv);

            using var encryptor = _aesCryptoProvider.CreateEncryptor(key.ToArray(), iv.ToArray());
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            using var sw = new BinaryWriter(cs);
            sw.Write(plaintext);
            cs.FlushFinalBlock();

            return Concat(iv.ToArray(), ms.ToArray());
        }

        private byte[] Concat(byte[] first, byte[] second)
        {
            var destination = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, destination, 0, first.Length);
            Buffer.BlockCopy(second, 0, destination, first.Length, second.Length);
            return destination;
        }

        private byte[] HmacSha512(byte[] key, params byte[][] authenticateMe)
        {
            using var ms = new MemoryStream();
            using var hmacSha512 = new HMACSHA512(key);
            hmacSha512.Initialize();
            foreach (var bytes in authenticateMe)
            {
                ms.Write(bytes);
            }

            return hmacSha512.ComputeHash(ms.ToArray());
        }
    }
}
