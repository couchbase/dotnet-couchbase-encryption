using System;
using System.IO;
using Couchbase.Extensions.Encryption.Stores;
using Xunit;
using Xunit.Abstractions;

namespace Couchbase.Extensions.Encryption.UnitTests.Stores
{
    public class FileKeyStoreTests : IDisposable
    {
        private readonly ITestOutputHelper output;
        private readonly string _keyname = "thekeyname";

        public FileKeyStoreTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Fact]
        public void Test_StoreKey()
        {
            var keystore = new FileSystemKeyStore();
            keystore.StoreKey(_keyname, "thekeyvalue");
        }

        [Fact]
        public void Test_GetKey()
        {
            Test_StoreKey();
            var keystore = new FileSystemKeyStore();
            var key = keystore.GetKey(_keyname);
            Assert.Equal("thekeyvalue", key);
        }

        public void Dispose()
        {
            try
            {
                File.Delete(_keyname + ".dat");
            }
            catch (Exception e)
            {
                output.WriteLine(e.ToString());
            }
        }
    }
}

#region [License information]
/* ************************************************************

 *    Copyright (c) 2018 Couchbase, Inc.
 *
 *    Use of this software is subject to the Couchbase Inc.
 *    Enterprise Subscription License Agreement which may be found
 *    at https://www.couchbase.com/ESLA-11132015.

 * ************************************************************/
#endregion
