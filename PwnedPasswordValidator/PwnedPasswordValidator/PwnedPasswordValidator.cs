using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace PwnedPasswordValidator
{
    /// <inheritdoc />
    /// <summary>
    /// Custom validator to avoid password that have appeared in known data breaches
    /// </summary>
    /// <typeparam name="TUser">Application user object</typeparam>
    public class PwnedPasswordValidator<TUser> : IPasswordValidator<TUser>
        where TUser : IdentityUser
    {
        private readonly IPwnedPasswordClient _pwnedClient;

        /// <inheritdoc />
        public PwnedPasswordValidator(IPwnedPasswordClient client)
        {
            _pwnedClient = client;
        }

        /// <inheritdoc />
        /// <summary>
        /// Checks if desired password is present in haveibeenpwned.com database. A failed IdentityResult is returned with Code "PwnedPassword" if that is true.
        /// </summary>
        /// <param name="manager">User manager for application users</param>
        /// <param name="user">Application user</param>
        /// <param name="password">Intended new password</param>
        /// <returns>IdentityResult</returns>
        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            var isPwned = await _pwnedClient.HasPasswordBeenPwned(password);

            if (isPwned)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = ErrorCodes.PwnedPassword,
                    Description = "Chosen password has appeared in a data breach."
                });
            }

            return IdentityResult.Success;
        }
    }
}
