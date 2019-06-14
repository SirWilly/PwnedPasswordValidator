using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PwnedPasswordValidator
{
    internal static class CryptographyExtensions
    {
        internal static string GetSha1Hash(this string value)
        {
            using (var sha1 = new SHA1Managed())
            {
                var hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(value));
                return string.Concat(hashBytes.Select(b => b.ToString("x2")));
            }
        }
    }
}
