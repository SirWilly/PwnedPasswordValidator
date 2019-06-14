using System;
using Microsoft.AspNetCore.Identity;

namespace PwnedPasswordValidator.Tests
{
    public sealed class TestUser : IdentityUser
    {
        public TestUser()
        {
            Id = Guid.NewGuid().ToString();
        }

        public TestUser(string userName) : this()
        {
            UserName = userName;
        }
    }
}
