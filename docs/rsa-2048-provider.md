# RSA-2048 with OAEP-SHA1 Padding

The `RsaCryptoProvider` provides asymmetric key encryption using RSA-2048 and OEAP-SHA1 padding.

## Parameters

The important parameters for `RsaCryptoProvider` are:

 - PublicKeyName - the name of the public key used to look up the public key in the key store provider.
 - PrivateKeyName - the name of the private key used to look up the private key in the key store provider.

Keys can be generated using OpenSsl commands. For Windows a .pfx must be used. The `X509CertificateKeyStore` provides integration with x509 certificates. 

## Configuration

To use the RsaCryptoProvider in your code, you will have to add it to your Couchbase SDK configuration. Note that config file based configuration is not currently supported, but will likely be in an upcoming release. To do this you will call the ClientConfiguration.EnableFieldEncryption method and define alias to use for the configuration as well as the AesCryptoProvider and a Key store. You will also provide the public key name and the siging key name:

```C#

var cert = new X509Certificate2("public_privatekey.pfx", "password",
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

var config = new ClientConfiguration();
config.EnableFieldEncryption(new KeyValuePair<string, ICryptoProvider>("MyProvider",
    new RsaCryptoProvider(new X509CertificateKeyStore(cert)
    {
        PrivateKeyName = "MyPrivateKeyName",
        PublicKeyName = "MyPublicKeyName"
    })
    {
        PrivateKeyName = "MyPrivateKeyName",
        PublicKeyName = "MyPublicKeyName"
    }));
```

This configuration is for the alias "MyProvider" - this will be used to look up the provider at runtime and perform encyrption on a property of a POCO adorned with the `EncryptedFieldAttribute`. For a key store we are using the `X509CertificateKeyStore` and a PFX file (Personal Exchange Format) with private and public keys. The `PublicKeyName` and `PrivateKeyName` fields must be populated, since they will map to the keys to use for encryption and authentication of the payload.

There is a bit of redundency there setting the private and public key names on both the `ICryptoProvider` and the `IKeyStoreProvider` here; there is an [open ticket](https://github.com/couchbase/dotnet-couchbase-encryption/issues/11) for using defaults for certain key stores that only contain one set of private/public keys. 


## Annotating your POCO for Encryption

In order for encryption to take place, the fields which are to be encrypted must be annoted with the `EncryptedFieldAttribute`:

```C#
public class Poco
{
    [EncryptedField(Provider = "MyProvider")]
    public string Bar { get; set; }

    [EncryptedField(Provider = "MyProvider")]
    public int Foo { get; set; }

    [EncryptedField(Provider = "MyProvider")]
    public List<int> Baz { get; set; }

    [EncryptedField(Provider = "MyProvider")]
    public PocoMoco ChildObject { get; set; }

    public string Fizz { get; set; }
}
```
Fields that are not annotated, will not be encrypted and will be stored as plain text. The `Provider` property of the annotation must match the alias of the provider that was configured.

## Performing Encryption and Decryption

Encryption is peformed during the serialization process of the JSON document body before sending the data over the wire - in couchbase it is stored encrypted. When the document is read from Couchbase Server, it will be decrypted during the deserialization process after coming over the network.

```C#
var bucket = cluster.OpenBucket();
var poco = new Poco
{
    Bar = "Bar",
    Foo = 90,
    ChildObject = new PocoMoco
    {
        Bar = "Bar2"
    },
    Fizz = "fizz",
    Baz = new List<int> {3, 4}
};

//encryption will be applied before sending to Couchbase
var result = bucket.Upsert("thepoco", poco);

...

//decryption will happen when the document has been recieved 
var get = bucket.Get<Poco>("thepoco");
```

The process is transparent from perspective of the application. 