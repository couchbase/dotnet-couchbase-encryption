using System.Net.WebSockets;
using System.Text;
using System.Text.Unicode;
using Xunit;

namespace Couchbase.Encryption.UnitTests
{
    public class DefaultCryptoManagerTests
    {
        public static string MangledFieldName ="encrypted$fieldName";
        public static string FieldName = "fieldName";
        public static string CustomFieldNamePrefix = "custom$";
        public static string CustomMangledFieldName = "custom$fieldName";

        [Fact]
        public void Test_Mangle()
        {
            var cryptoManager = DefaultCryptoManager.Builder().Build();
            var mangled = cryptoManager.Mangle(FieldName);

            Assert.Equal(MangledFieldName, mangled);
        }

        [Fact]
        public void Test_Mangle_Custom_Prefix()
        {
            var cryptoManager = DefaultCryptoManager.Builder().EncryptedFieldNamePrefix(CustomFieldNamePrefix).Build();
            var mangled = cryptoManager.Mangle(FieldName);

            Assert.Equal(CustomMangledFieldName, mangled);
        }

        [Fact]
        public void Test_Demangle()
        {
            var cryptoManager = DefaultCryptoManager.Builder().Build();
            var mangled = cryptoManager.Demangle(MangledFieldName);

            Assert.Equal(FieldName, mangled);
        }

        [Fact]
        public void Test_Demangle_Custom_Prefix()
        {
            var cryptoManager = DefaultCryptoManager.Builder().EncryptedFieldNamePrefix(CustomFieldNamePrefix).Build();
            var mangled = cryptoManager.Demangle(CustomMangledFieldName);

            Assert.Equal(FieldName, mangled);
        }

        [Fact]
        public void Test_IsMangled_True_When_Mangled()
        {
            var cryptoManager = DefaultCryptoManager.Builder().Build();

            Assert.True(cryptoManager.IsMangled(MangledFieldName));
        }

        [Fact]
        public void Test_IsMangled_False_When_Not_Mangled()
        {
            var cryptoManager = DefaultCryptoManager.Builder().Build();

            Assert.False(cryptoManager.IsMangled(FieldName));
        }
    }
}
