﻿using System;

namespace Couchbase.Encryption.Errors
{
    public sealed class EncrypterNotFoundException : CouchbaseException
    {
        public EncrypterNotFoundException(string alias, string message) : base(message)
        {
            Alias = alias;
        }

        public string Alias { get; }

        public static EncrypterNotFoundException Create(string alias)
        {
            return new EncrypterNotFoundException(alias,
                DefaultCryptoManager.DefaultEncrypterAlias.Equals(alias, StringComparison.InvariantCultureIgnoreCase)
                    ? "No default encrypter was registered. Please specify an encrypter or register a default encrypter."
                    : $"Missing encrypter for alias '{alias}'.");
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
