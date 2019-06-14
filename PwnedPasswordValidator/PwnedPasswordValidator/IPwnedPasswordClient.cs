using System.Threading.Tasks;

namespace PwnedPasswordValidator
{
    /// <summary>
    /// A client for communicating with Troy Hunt's HaveIBeenPwned API
    /// </summary>
    public interface IPwnedPasswordClient
    {
        /// <summary>
        /// Checks if a provided password has appeared in a known data breach
        /// </summary>
        /// <param name="password">The password to check</param>
        /// <returns></returns>
        Task<bool> HasPasswordBeenPwned(string password);
    }
}
