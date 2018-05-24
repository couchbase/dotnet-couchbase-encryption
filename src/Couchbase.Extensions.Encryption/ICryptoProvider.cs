
namespace Couchbase.Extensions.Encryption
{
    /// <summary>
    /// Provides an interface for implementing a cryptographic algorithm for Field Level Encryption.
    /// </summary>
    public interface ICryptoProvider
    {
        /// <summary>
        /// The key store to retrieve the keys used for encryption and signing the encrypted data if required.
        /// </summary>
        IKeystoreProvider KeyStore { get; set; }

        /// <summary>
        /// Decrypts a byte array.
        /// </summary>
        /// <param name="encryptedBytes">A base64 encoded byte array.</param>
        /// <param name="iv">The initialization vector to use.</param>
        /// <param name="keyName">The key name that will be used to look up the encryption key from the <see cref="IKeystoreProvider"/>.</param>
        /// <returns>A decrypted, UTF8 encoded byte array.</returns>
        byte[] Decrypt(byte[] encryptedBytes, byte[] iv, string keyName = null);

        /// <summary>
        /// Encrypts a UTF8 byte array.
        /// </summary>
        /// <param name="plainBytes">A UTF8 encoded byte array.</param>
        /// <param name="iv">The initialization vector to use.</param>
        /// <returns>An encrypted UTF8 byte array.</returns>
        byte[] Encrypt(byte[] plainBytes, out byte[] iv);

        /// <summary>
        /// Generates a signature from a byte array.
        /// </summary>
        /// <param name="cipherBytes">The byte array used to generate the signature from.</param>
        /// <returns></returns>
        byte[] GetSignature(byte[] cipherBytes);

        /// <summary>
        /// The name or alias of the configured <see cref="ICryptoProvider"/> - for example 'MyProvider'.
        /// </summary>
        string ProviderName { get; set; }

        /// <summary>
        /// The name of the encryption key.
        /// </summary>
        string PublicKeyName { get; set; }

        /// <summary>
        /// The name of the private if required for an asymmetric algorithm
        /// </summary>
        string PrivateKeyName { get; set; }

        /// <summary>
        /// The name of the password or key used for signing if required.
        /// </summary>
        string SigningKeyName { get; set; }

        /// <summary>
        /// True if the algorithm requires a signature to be generated and compared.
        /// </summary>
        bool RequiresAuthentication { get; }

        /// <summary>
        /// The name of the algorithmn that the provider supports
        /// </summary>
        string AlgorithmName { get; }
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
