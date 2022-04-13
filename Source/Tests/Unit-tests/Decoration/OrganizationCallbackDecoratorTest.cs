using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.DirectoryServices;
using TestHelpers.Mocks.Logging;
using UnitTests.Mocks.DirectoryServices;

namespace UnitTests.Decoration
{
	[TestClass]
	public class OrganizationCallbackDecoratorTest
	{
		#region Properties

		protected internal virtual string ActiveDirectoryEmailAttributeName => "mail";
		protected internal virtual string ActiveDirectoryUserPrincipalNameAttributeName => "userPrincipalName";
		protected internal virtual string AuthenticationScheme => "Unit-test-authentication-scheme";
		protected internal virtual string AuthenticationType => "Unit-test";
		protected internal virtual string Email => "first-name.last-name.mail@example.org";
		protected internal virtual string Identity => "identity";
		protected internal virtual string IdentityClaimType => "identityClaim";
		protected internal virtual string IdentityPrefix => "prefix-";
		protected internal virtual string PrefixedIdentity => $"{this.IdentityPrefix}{this.Identity}";
		protected internal virtual string UserPrincipalName => "first-name.last-name.upn@example.org";

		#endregion

		#region Methods

		protected internal virtual async Task<AuthenticateResult> CreateAuthenticateResultAsync(params IClaimBuilder[] claims)
		{
			var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims.Select(claim => claim.Build()), this.AuthenticationType));
			var authenticationTicket = new AuthenticationTicket(claimsPrincipal, this.AuthenticationScheme);

			return await Task.FromResult(AuthenticateResult.Success(authenticationTicket));
		}

		protected internal virtual async Task<IClaimBuilderCollection> CreateInitialClaimsAsync()
		{
			var initialClaims = new ClaimBuilderCollection
			{
				new ClaimBuilder
				{
					Type = this.IdentityClaimType,
					Value = this.PrefixedIdentity
				}
			};

			return await Task.FromResult(initialClaims);
		}

		protected internal virtual async Task<OrganizationCallbackDecorator> CreateOrganizationCallbackDecoratorAsync(IActiveDirectory activeDirectory = null, ILoggerFactory loggerFactory = null)
		{
			activeDirectory ??= Mock.Of<IActiveDirectory>();
			loggerFactory ??= Mock.Of<ILoggerFactory>();

			return await Task.FromResult(new OrganizationCallbackDecorator(activeDirectory, loggerFactory));
		}

		[TestMethod]
		public async Task DecorateAsync_FromClaims_Test()
		{
			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var activeDirectory = new ActiveDirectoryMock();
				var organizationCallbackDecorator = await this.CreateOrganizationCallbackDecoratorAsync(activeDirectory: activeDirectory, loggerFactory: loggerFactory);
				organizationCallbackDecorator.IdentityClaimType = this.IdentityClaimType;
				organizationCallbackDecorator.IdentityPrefix = this.IdentityPrefix;

				var claims = await this.CreateInitialClaimsAsync();
				Assert.AreEqual(1, claims.Count);
				await organizationCallbackDecorator.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(1, claims.Count);

				activeDirectory.Result.Add(this.ActiveDirectoryEmailAttributeName, this.Email);
				claims = await this.CreateInitialClaimsAsync();
				Assert.AreEqual(1, claims.Count);
				await organizationCallbackDecorator.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(2, claims.Count);
				var firstClaim = claims[0];
				Assert.AreEqual(this.IdentityClaimType, firstClaim.Type);
				Assert.AreEqual(this.PrefixedIdentity, firstClaim.Value);
				var secondClaim = claims[1];
				Assert.AreEqual(ClaimTypes.Email, secondClaim.Type);
				Assert.AreEqual(this.Email, secondClaim.Value);

				activeDirectory.Result.Clear();
				activeDirectory.Result.Add(this.ActiveDirectoryUserPrincipalNameAttributeName, this.UserPrincipalName);
				claims = await this.CreateInitialClaimsAsync();
				Assert.AreEqual(1, claims.Count);
				await organizationCallbackDecorator.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(2, claims.Count);
				firstClaim = claims[0];
				Assert.AreEqual(this.IdentityClaimType, firstClaim.Type);
				Assert.AreEqual(this.PrefixedIdentity, firstClaim.Value);
				secondClaim = claims[1];
				Assert.AreEqual(ClaimTypes.Upn, secondClaim.Type);
				Assert.AreEqual(this.UserPrincipalName, secondClaim.Value);

				activeDirectory.Result.Clear();
				activeDirectory.Result.Add(this.ActiveDirectoryEmailAttributeName, this.Email);
				activeDirectory.Result.Add(this.ActiveDirectoryUserPrincipalNameAttributeName, this.UserPrincipalName);
				claims = await this.CreateInitialClaimsAsync();
				Assert.AreEqual(1, claims.Count);
				await organizationCallbackDecorator.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(3, claims.Count);
				firstClaim = claims[0];
				Assert.AreEqual(this.IdentityClaimType, firstClaim.Type);
				Assert.AreEqual(this.PrefixedIdentity, firstClaim.Value);
				secondClaim = claims[1];
				Assert.AreEqual(ClaimTypes.Email, secondClaim.Type);
				Assert.AreEqual(this.Email, secondClaim.Value);
				var thirdClaim = claims[2];
				Assert.AreEqual(ClaimTypes.Upn, thirdClaim.Type);
				Assert.AreEqual(this.UserPrincipalName, thirdClaim.Value);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_FromPrincipal_Test()
		{
			var claims = new ClaimBuilderCollection();
			var principalClaims = await this.CreateInitialClaimsAsync();

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var activeDirectory = new ActiveDirectoryMock();
				var organizationCallbackDecorator = await this.CreateOrganizationCallbackDecoratorAsync(activeDirectory: activeDirectory, loggerFactory: loggerFactory);
				organizationCallbackDecorator.IdentityClaimType = this.IdentityClaimType;
				organizationCallbackDecorator.IdentityPrefix = this.IdentityPrefix;

				Assert.AreEqual(0, claims.Count);
				await organizationCallbackDecorator.DecorateAsync(await this.CreateAuthenticateResultAsync(principalClaims.ToArray()), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(0, claims.Count);

				activeDirectory.Result.Add(this.ActiveDirectoryEmailAttributeName, this.Email);
				Assert.AreEqual(0, claims.Count);
				await organizationCallbackDecorator.DecorateAsync(await this.CreateAuthenticateResultAsync(principalClaims.ToArray()), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(1, claims.Count);
				var firstClaim = claims[0];
				Assert.AreEqual(ClaimTypes.Email, firstClaim.Type);
				Assert.AreEqual(this.Email, firstClaim.Value);

				activeDirectory.Result.Clear();
				activeDirectory.Result.Add(this.ActiveDirectoryUserPrincipalNameAttributeName, this.UserPrincipalName);
				claims.Clear();
				Assert.AreEqual(0, claims.Count);
				await organizationCallbackDecorator.DecorateAsync(await this.CreateAuthenticateResultAsync(principalClaims.ToArray()), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(1, claims.Count);
				firstClaim = claims[0];
				Assert.AreEqual(ClaimTypes.Upn, firstClaim.Type);
				Assert.AreEqual(this.UserPrincipalName, firstClaim.Value);

				activeDirectory.Result.Clear();
				activeDirectory.Result.Add(this.ActiveDirectoryEmailAttributeName, this.Email);
				activeDirectory.Result.Add(this.ActiveDirectoryUserPrincipalNameAttributeName, this.UserPrincipalName);
				claims.Clear();
				Assert.AreEqual(0, claims.Count);
				await organizationCallbackDecorator.DecorateAsync(await this.CreateAuthenticateResultAsync(principalClaims.ToArray()), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(2, claims.Count);
				firstClaim = claims[0];
				Assert.AreEqual(ClaimTypes.Email, firstClaim.Type);
				Assert.AreEqual(this.Email, firstClaim.Value);
				var secondClaim = claims[1];
				Assert.AreEqual(ClaimTypes.Upn, secondClaim.Type);
				Assert.AreEqual(this.UserPrincipalName, secondClaim.Value);
			}
		}

		[TestMethod]
		public async Task IdentifierKind_ShouldReturnSamAccountNameByDefault()
		{
			Assert.AreEqual(IdentifierKind.SamAccountName, (await this.CreateOrganizationCallbackDecoratorAsync()).IdentifierKind);
		}

		[TestMethod]
		public async Task IdentityClaimType_ShouldReturnNullByDefault()
		{
			Assert.IsNull((await this.CreateOrganizationCallbackDecoratorAsync()).IdentityClaimType);
		}

		[TestMethod]
		public async Task IdentityPrefix_ShouldReturnNullByDefault()
		{
			Assert.IsNull((await this.CreateOrganizationCallbackDecoratorAsync()).IdentityPrefix);
		}

		#endregion
	}
}