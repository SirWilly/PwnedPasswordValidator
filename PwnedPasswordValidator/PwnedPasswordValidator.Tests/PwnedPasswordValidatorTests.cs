using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Moq;
using NUnit.Framework;

namespace PwnedPasswordValidator.Tests
{
    public class PwnedPasswordValidatorTests
    {
        private static UserManager<TestUser> _userManager;

        [SetUp]
        public void SetUp()
        {
            _userManager = UserManagerMockFactory.MockUserManager<TestUser>().Object;
        }

        [Test]
        public async Task ValidateAsync_ShouldFail()
        {
            var client = new Mock<IPwnedPasswordClient>();
            client.Setup(x => x.HasPasswordBeenPwned(It.IsAny<string>()))
                .ReturnsAsync(true);
            var pwnedValidator = new PwnedPasswordValidator<TestUser>(client.Object);

            var identityResult = await pwnedValidator.ValidateAsync(_userManager, null, "password");

            Assert.IsFalse(identityResult.Succeeded);
            Assert.AreEqual(identityResult.Errors.First().Code, ErrorCodes.PwnedPassword);
        }

        [Test]
        public async Task ValidateAsync_ShouldSucceed()
        {
            var client = new Mock<IPwnedPasswordClient>();
            client.Setup(x => x.HasPasswordBeenPwned(It.IsAny<string>()))
                .ReturnsAsync(false);
            var pwnedValidator = new PwnedPasswordValidator<TestUser>(client.Object);

            var identityResult = await pwnedValidator.ValidateAsync(_userManager, null, "password");

            Assert.IsTrue(identityResult.Succeeded);
        }
    }
}