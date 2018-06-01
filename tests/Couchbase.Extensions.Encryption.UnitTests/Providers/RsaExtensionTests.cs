using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Couchbase.Extensions.Encryption.Providers;
using Xunit;

namespace Couchbase.Extensions.Encryption.UnitTests.Providers
{
    public class RsaExtensionTests
    {
        [Fact]
        public void FromXmlStrig()
        {
            var xml = "<?xml version=\"1.0\"?><RSAKeyValue><Modulus>syjVFLv7bMfDFFwLpLG/3gNSuZJV8/Kh0q6QPUKyHp6mzxL5IMwSWtNv5kICyuGroDeBvOUBKi6+U7beOKfY5dbG/0iss86RIRFc7PgQPjGbwQtm7kaSmorw7CxmvuC2U2Vup8c4zPyuz2wBrYZGlcBT5QoQQsnGs68D/YoZvUk=</Modulus><Exponent>AQAB</Exponent><P>7gkEenLmtni0Yf2uaCb1sePqdqV99y5Z6m5K1Y87lBioEMFCREi7UbegHKrhPPm9OOWLALMGYtC7T6fRzYBwnw==</P><Q>wK5M/xOla20u5eqU7ItNGIt1vYzOr+HJQVtKB2ORIn0fsF46EF+Ls9A7z5HqurdBd4hS94RTxO3384KCTYEBFw==</Q><DP>AN8nlQs2rRRkFLfJG7iIzc333dddTrpsud8NhxqvLSup8eXDSFy70uDJRVGa4Y5IkxzEFYySSWpaRUBoFEiUIQ==</DP><DQ>Vd6YE+mWhBzBlNeJjS27qx+j1ljlV/8A6S6c/FQEP2GR+NDVgayDHxzDOwtll9bJx1Kq3wJLLu163jwghBfk+w==</DQ><InverseQ>oPucjbmUK8B3K2CbmI6fx64IG6Bf+myTuYj0mXNpKmLMjm8RgHnctJaQoHdoywKD2GGGaO9XIu+khhPvYUAc2w==</InverseQ><D>B5jUqENsXul9mTBqAfrTkvt7F4lgAa8pM4DZdu+MFAZQNnmsfLqKkLVkilQEQEwfdfTEmJjxWrOOuIgJlkdvyAT23TzqdkY5IK6ZNtRJmO6AED8v6SaVZrBvP6GL3hnxNVqrTMFX5YZcbXjehV4Bc91luKkGFJ9CTZpFKY0fb50=</D></RSAKeyValue>";
            var rsaParameters = RSAExtensions.FromXmlString(xml);
            var rsa = RSA.Create();
            rsa.ImportParameters(rsaParameters);
        }
    }
}
