﻿using System;

namespace Couchbase.Encryption.Attributes
{
    public class EncryptedFieldAttribute : Attribute
    {
        public string KeyName { get; set; }

        public string LegacySigningKeyName { get; set; }
    }
}
