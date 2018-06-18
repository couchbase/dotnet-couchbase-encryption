# AES-256 with CBC padding and SHA-256 signing

The `AesCryptoProvider` provides symmetric key cryptography using AES-256 algorithm with CBC padding and SHA-256 signing of the payload.

## Parameters
Like all crypto providers, AesCryptoProvider inherits CryptoProviderBase which has properties for public and private keys, signing key or password and other properties, however the PublicKeyName and the SecretKeyName are the two important properties:

- **SecretKeyName:** used for validating the payload before decrypting to ensure that it hasn't changed.
- **PublicKeyName:** the name of the key. The supported key size is 256 bits.

## Configuration
To use the AesCryptoProvider in your code, you will have to add it to your Couchbase SDK configuration. Note that config file based configuration is not currently supported, but will likely be in an upcoming release. To do this you will call the ClientConfiguration.EnableFieldEncryption method and define alias to use for the configuration as well as the AesCryptoProvider and a Key store. You will also provide the public key name and the siging key name:

```C#
var config = new ClientConfiguration();
config.EnableFieldEncryption(new KeyValuePair<string, ICryptoProvider>("MyProvider",
    new AesCryptoProvider(new InsecureKeyStore(
        new KeyValuePair<string, string>("publickey", "!mysecretkey#9^5usdk39d&dlf)03sL",
        new KeyValuePair<string, string>("mysecret", "myauthpassword")))
    {
        PublicKeyName = "publickey",
        SigningKeyName = "mysecret"
    }));
```

This configuration is for the alias "MyProvider" - this will be used to look up the provider at runtime and perform encyrption on a property of a POCO adorned with the `EncryptedFieldAttribute`. For simplicity we are using the `InsecureKeyStore` which is simply and in-memory key store that does not protect the keys - they stord as plain text - which is suitable for this example. The `PublicKeyName` and `PrivateKeyName` fields must be populated, since they will map to the keys to use for encryption and authentication of the payload.

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