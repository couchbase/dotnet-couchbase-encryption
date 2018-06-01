using System;
using System.Security.Cryptography.X509Certificates;
using Couchbase.Extensions.Encryption.Providers;

namespace Couchbase.Extensions.Encryption.Stores
{
    public class X509KeyStore : IKeystoreProvider
    {
        private readonly X509Certificate2 _x509Certificate2;

        public X509KeyStore(X509Certificate2 x509Certificate2)
        {
            _x509Certificate2 = x509Certificate2;
        }

        public X509KeyStore(string path, string password) :
            this(new X509Certificate2(path, password))
        {
        }

        public string GetKey(string keyname)
        {
            var isPrivate = keyname == "PrivateKey";
#if NETSTANDARD
            return _x509Certificate2.GetRSAPrivateKey().ExportParameters(isPrivate).ToXmlString(isPrivate);
#else
            return _x509Certificate2.PrivateKey.ToXmlString(isPrivate);
#endif
        }

        public void StoreKey(string keyname, string key)
        {
            throw new NotSupportedException();
        }

        internal X509Certificate2 GetCertificate()
        {
            return _x509Certificate2;
        }
    }
}
