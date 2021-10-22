using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Couchbase.Encryption.Legacy
{
    public static class RsaExtensions
    {
        public static byte[] ToBytes(this RSAParameters parameters, bool includePrivateParameters)
        {
            return Encoding.UTF8.GetBytes(ToXmlString(parameters, includePrivateParameters));
        }

        public static RSAParameters FromBytes(this byte[] keyBytes, bool includePrivateParameters)
        {
            return FromXmlString(Encoding.UTF8.GetString(keyBytes));
        }

        public static string ToXmlString(this RSAParameters parameters, bool includePrivateParameters)
        {
            if (includePrivateParameters)
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

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                Convert.ToBase64String(parameters.Modulus),
                Convert.ToBase64String(parameters.Exponent));
        }

        public static RSAParameters FromXmlString(string xml)
        {
            var rsaParameters = new RSAParameters();
            using var reader = XmlReader.Create(new StringReader(xml));
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

            return rsaParameters;
        }
    }
}


/* ************************************************************
 *
 *    @author Couchbase <info@couchbase.com>
 *    @copyright 2021 Couchbase, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 * ************************************************************/
