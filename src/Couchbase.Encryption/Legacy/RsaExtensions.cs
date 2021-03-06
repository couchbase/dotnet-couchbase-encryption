﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml;

namespace Couchbase.Encryption.Legacy
{
    public static class RsaExtensions
    {
       /* public static string GetKey(this X509CertificateKeyStore certificateKeyStore, bool isPrivateKey)
        {
            ;
#if NETSTANDARD
            return certificateKeyStore.GetCertificate().GetRSAPrivateKey().ExportParameters(isPrivateKey).ToXmlString(isPrivateKey);
#else
            return certificateKeyStore.GetCertificate().PrivateKey.ToXmlString(isPrivateKey);
#endif
        }*/

        public static string ToXmlString(this RSAParameters parameters, bool includePrivateParameters)
        {
            if (includePrivateParameters)
            {
                return string.Format(
                    "<?xml version=\"1.0\"?><RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                    Convert.ToBase64String(parameters.Modulus),
                    Convert.ToBase64String(parameters.Exponent),
                    Convert.ToBase64String(parameters.P),
                    Convert.ToBase64String(parameters.Q),
                    Convert.ToBase64String(parameters.DP),
                    Convert.ToBase64String(parameters.DQ),
                    Convert.ToBase64String(parameters.InverseQ),
                    Convert.ToBase64String(parameters.D));
            }
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                Convert.ToBase64String(parameters.Modulus),
                Convert.ToBase64String(parameters.Exponent));
        }

        public static RSAParameters FromXmlString(string xml)
        {
            var rsaParameters = new RSAParameters();
            using (var reader = XmlReader.Create(new StringReader(xml)))
            {
                while (reader.Read())
                    if (reader.NodeType == XmlNodeType.Element)
                        switch (reader.Name)
                        {
                            case "Modulus":
                                reader.Read();
                                rsaParameters.Modulus = Convert.FromBase64String(reader.Value);
                                break;
                            case "Exponent":
                                reader.Read();
                                rsaParameters.Exponent = Convert.FromBase64String(reader.Value);
                                break;
                            case "P":
                                reader.Read();
                                rsaParameters.P = Convert.FromBase64String(reader.Value);
                                break;
                            case "Q":
                                reader.Read();
                                rsaParameters.Q = Convert.FromBase64String(reader.Value);
                                break;
                            case "DP":
                                reader.Read();
                                rsaParameters.DP = Convert.FromBase64String(reader.Value);
                                break;
                            case "DQ":
                                reader.Read();
                                rsaParameters.DQ = Convert.FromBase64String(reader.Value);
                                break;
                            case "InverseQ":
                                reader.Read();
                                rsaParameters.InverseQ = Convert.FromBase64String(reader.Value);
                                break;
                            case "D":
                                reader.Read();
                                rsaParameters.D = Convert.FromBase64String(reader.Value);
                                break;
                        }
            }

            return rsaParameters;
        }
    }
}
