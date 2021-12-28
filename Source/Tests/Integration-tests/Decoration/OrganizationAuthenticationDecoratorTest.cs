using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.DirectoryServices;

namespace IntegrationTests.Decoration
{
	[TestClass]
	public class OrganizationAuthenticationDecoratorTest : AuthenticationDecoratorTestBase
	{
		#region Methods

		protected internal virtual AuthenticateResult CreateAuthenticateResult(ClaimsPrincipal principal)
		{
			return AuthenticateResult.Success(new AuthenticationTicket(principal, "Ticket-authentication-scheme"));
		}

		protected internal virtual OrganizationAuthenticationDecorator CreateOrganizationAuthenticationDecorator()
		{
			return this.CreateOrganizationAuthenticationDecorator(Mock.Of<ILoggerFactory>());
		}

		protected internal virtual OrganizationAuthenticationDecorator CreateOrganizationAuthenticationDecorator(ILoggerFactory loggerFactory)
		{
			return this.CreateOrganizationAuthenticationDecorator(new ExtendedAuthenticationOptions(), loggerFactory);
		}

		protected internal virtual OrganizationAuthenticationDecorator CreateOrganizationAuthenticationDecorator(ExtendedAuthenticationOptions authenticationOptions, ILoggerFactory loggerFactory)
		{
			var options = Options.Create(authenticationOptions);

			return new OrganizationAuthenticationDecorator(new ActiveDirectory(options), options, loggerFactory);
		}

		[TestMethod]
		public void DecorateAsync_Test()
		{
			const string authenticationScheme = "Organization";

			var serviceProvider = this.ConfigureServices("Organization-Decorator");
			var authenticationOptions = serviceProvider.GetRequiredService<IOptions<ExtendedAuthenticationOptions>>().Value;

			Assert.AreEqual(200, authenticationOptions.CallbackDecorators.ElementAt(1).Value.AuthenticationSchemes.First().Value);

			var organizationAuthenticationDecorator = (OrganizationAuthenticationDecorator)serviceProvider.GetRequiredService<IDecorationLoader>().GetCallbackDecoratorsAsync(authenticationScheme).Result.ElementAt(1);

			Assert.IsNotNull(organizationAuthenticationDecorator);
			Assert.AreEqual("organizationIdentity", organizationAuthenticationDecorator.IdentityClaimType);
			Assert.AreEqual("AB0123456789-", organizationAuthenticationDecorator.IdentityPrefix);

			var identity = organizationAuthenticationDecorator.IdentityPrefix;
			var identityNameParts = WindowsIdentity.GetCurrent().Name.Split('\\', 2).ToArray();
			if(identityNameParts.Length == 2)
				identity += identityNameParts[1];

			var claims = new ClaimBuilderCollection();
			var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("organizationIdentity", identity) }, "Test"));
			var authenticateResult = this.CreateAuthenticateResult(principal);

			organizationAuthenticationDecorator.DecorateAsync(authenticateResult, authenticationScheme, claims, null).Wait();

			Assert.AreEqual(2, claims.Count);
		}

		[TestMethod]
		public void DecorateAsync_WithoutOptions_Test()
		{
			const string authenticationScheme = "Organization";

			var serviceProvider = this.ConfigureServices("Organization-Decorator-Without-Options");
			var authenticationOptions = serviceProvider.GetRequiredService<IOptions<ExtendedAuthenticationOptions>>().Value;

			Assert.AreEqual(200, authenticationOptions.CallbackDecorators.ElementAt(1).Value.AuthenticationSchemes.First().Value);

			var organizationAuthenticationDecorator = (OrganizationAuthenticationDecorator)serviceProvider.GetRequiredService<IDecorationLoader>().GetCallbackDecoratorsAsync(authenticationScheme).Result.ElementAt(1);

			Assert.IsNotNull(organizationAuthenticationDecorator);
			Assert.IsNull(organizationAuthenticationDecorator.IdentityClaimType);
			Assert.IsNull(organizationAuthenticationDecorator.IdentityPrefix);

			var identity = organizationAuthenticationDecorator.IdentityPrefix;
			var identityNameParts = WindowsIdentity.GetCurrent().Name.Split('\\', 2).ToArray();
			if(identityNameParts.Length == 2)
				identity += identityNameParts[1];

			var claims = new ClaimBuilderCollection();
			var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("organizationIdentity", identity) }, "Test"));
			var authenticateResult = this.CreateAuthenticateResult(principal);

			organizationAuthenticationDecorator.DecorateAsync(authenticateResult, authenticationScheme, claims, null).Wait();

			Assert.AreEqual(0, claims.Count);
		}

		#endregion
	}
}