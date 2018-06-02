# Couchbase Field Encryption for .NET SDK
Attribute based Field level encryption library for the .NET Couchbase SDK. Encrypted fields are protected in transit and at rest. Fields are transparently decrypted when they are retrieved from Couchbase within the application. 

## Getting Started ##
Package is available on Nuget and supports .NETFramework 4.5, .NETStandard 1.5 and .NETStandard 2.0. To install use the NuGet Package Manager or CIL:

``` 
Install-Package Couchbase.Extensions.Encryption -Version 1.0.0-beta2
```

After installing the dependency, create a configuration to connect to your Couchbase cluster and configure the Key Store and Algorithm provider to use:

```C#
//define the key store
var keyStore = new InsecureKeyStore(
    new KeyValuePair<string, string>("publickey", "!mysecretkey#9^5usdk39d&dlf)03sL"),
    new KeyValuePair<string, string>("mysigningkey", "myauthpassword"));

//define the algorithm to use
var cryptoProvider = new AesCryptoProvider(keyStore)
{
    PublicKeyName = "publickey",
    SigningKeyName = "mysigningkey"
};

//Add the configuration
var config = new ClientConfiguration();
config.EnableFieldEncryption("MyAesProvider", cryptoProvider);

//create the Cluster object to connect to a bucket
var cluster = new Cluster(config);
var bucket = cluster.OpenBucket();
```

Couchbase Field Level Encryption (FLE) uses .NET Attributes to specify which field on a JSON document that is mapped to a POCO (Plain Old C# Object) to encrypt. Here is an example of a JSON document representing a Person and the POCO it is mapped to:

First the JSON:
```JSON
{
  "password": "ssloBeD12345",
  "firstName": "Ted",
  "lastName": "DeBloss",
  "userName": "DeblossTheBozz22",
  "age": 33,
  "type": "Person"
}
```
This JSON will be mapped to a POCO representing the JSON's structure with the `Password` property annotated with the `EnryptedFieldAttribute` to be encrypted:

```C#
private class Person
{
    //Annotate the field to be encrypted
    [EncryptedField(Provider = "MyAesProvider")]
    public string Password { get; set; }

    //The rest will be transported and stored unencrypted
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string UserName { get; set; }
    public int Age { get; set; }
}
```

The `EncryptedFieldAttribute` has a `Provider` property which maps to the crypto provider which was configured earlier. During the serialization process the attribute will be a signal for the crypto provider to perform encryption on the contents of the property; when the JSON document is read from the database, the field contents will be decrypted.

```C#
var person = new Person
{
    Age = 33,
    FirstName = "Ted",
    LastName = "DeBloss",
    UserName = "DeblossTheBozz22",
    Password = "ssloBeD12345"
};

//the Passwordf field will be sent and stored encrypted
var result = await bucket.InsertAsync("p1", person);

//The Password field will be returned encrypted but decrypted during deserialization
var result1 = await bucket.GetAsync("p1");
```
Above, a person instance is created from the Person POCO and sent to the database. Just before going over the wire, during the serialization process, the `EncryptedFieldAttribute` will be detected and the crypto provider will be engaged, taking the contents of the property and encrypting it. When `GetAsync` is called, the document will be fetched from the database and just after coming over the network, during the deserialization process, the contents of teh field will be decrypted transparently.

## Supported Algorithms

## Supported Key Stores