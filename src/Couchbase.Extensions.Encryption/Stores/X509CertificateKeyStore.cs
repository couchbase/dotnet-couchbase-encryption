using System;
using System.Security.Cryptography.X509Certificates;
#if NETSTANDARD
using Couchbase.Extensions.Encryption.Providers;
#endif

namespace Couchbase.Extensions.Encryption.Stores
{
    /// <summary>
    /// Represents an X.509 certificate key store for RSA cryptography.
    /// </summary>
    public class X509CertificateKeyStore : IKeystoreProvider
    {
        private readonly X509Certificate2 _x509Certificate2;

        public X509CertificateKeyStore(X509Certificate2 x509Certificate2)
        {
            _x509Certificate2 = x509Certificate2;
        }

        public X509CertificateKeyStore(string path, string password) :
            this(new X509Certificate2(path, password))
        {
        }

        /// <summary>
        /// Gets the key for a given keyname.
        /// </summary>
        /// <param name="keyname">The private or public key which much match the value of the <see cref="PrivateKeyName"/> or
        ///  <see cref="PublicKeyName"/> property that is configured.</param>
        /// <exception cref="CryptoKeyMisMatchException">Thrown if the passed in key name doesn't match the <see cref="PrivateKeyName"/> or
        ///  <see cref="PublicKeyName"/> property.</exception>
        /// <returns>An XML string representing the key.</returns>
        public string GetKey(string keyname)
        {
            if (string.Compare(keyname, PrivateKeyName, StringComparison.OrdinalIgnoreCase) != 0 &&
                string.Compare(keyname, PublicKeyName, StringComparison.OrdinalIgnoreCase) != 0)
            {
                throw new CryptoKeyMismatchException(keyname, PublicKeyName, PrivateKeyName);
            }
            var isPrivate = keyname == PrivateKeyName;
#if NETSTANDARD
            return _x509Certificate2.GetRSAPrivateKey().ExportParameters(isPrivate).ToXmlString(isPrivate);
#else
            return _x509Certificate2.PrivateKey.ToXmlString(isPrivate);
#endif
        }

        /// <summary>
        /// Not supported for this provider - keys are derived from the X.509 certificate and the
        /// <see cref="PrivateKeyName"/> and <see cref="PublicKeyName"/> values.
        /// </summary>
        /// <param name="keyname"></param>
        /// <param name="key"></param>
        public void StoreKey(string keyname, string key)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Gets the X.509 that this key store has been configured with.
        /// </summary>
        /// <returns></returns>
        internal X509Certificate2 GetCertificate()
        {
            return _x509Certificate2;
        }

        /// <summary>
        /// The name of the public key.
        /// </summary>
        public string PublicKeyName { get; set; } = "PublicKeyName";

        /// <summary>
        /// The name of the private key.
        /// </summary>
        public string PrivateKeyName { get; set; } = "PrivateKeyName";
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
