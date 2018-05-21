namespace Couchbase.Extensions.Encryption
{
    public interface IKeystoreProvider
    {
        string GetKey(string keyname);

        void StoreKey(string keyname, string key);
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
