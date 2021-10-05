using System;

namespace Couchbase.Encryption
{
    internal static class EncryptionField
    {
        /// <summary>
        /// The “key-identifier” for resolving the key used to decrypt/encrypt from the KeyStore. See section on Key Management above.
        /// </summary>
        public static string KeyIdentifier = "kid";

        /// <summary>
        /// The algorithm used to encrypt/decrypt.
        /// </summary>
        public static string Algorithm = "alg";

        /// <summary>
        /// A Base64 encoded string that is the value from the field that has been encrypted.
        /// </summary>
        public static string CipherText = "ciphertext";

        /// <summary>
        /// Optional, required for AES. The HMAC signature of the following fields concatenating and
        /// then base64 encoding them: “alg”, “iv”, and “ciphertext”. Order is important and must be
        /// respected across all implementations.
        /// </summary>
        [Obsolete("Legacy from FLE 1.")]
        public static string Signature = "sig";

        /// <summary>
        /// Optional, required by AES. The Base64 encoded initialization vector used for the cipher-text.
        /// </summary>
        [Obsolete("Legacy from FLE 1.")]
        public static string InitializationVector = "iv";
    }
}
