using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.DirectoryServices.Protocols.Configuration;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.DirectoryServices;

namespace IntegrationTests.Decoration
{
	[TestClass]
	public class OrganizationCallbackDecoratorTest : AuthenticationDecoratorTestBase
	{
		#region Methods

		protected internal virtual AuthenticateResult CreateAuthenticateResult(ClaimsPrincipal principal)
		{
			return AuthenticateResult.Success(new AuthenticationTicket(principal, "Ticket-authentication-scheme"));
		}

		protected internal virtual OrganizationCallbackDecorator CreateOrganizationCallbackDecorator()
		{
			return this.CreateOrganizationCallbackDecorator(Mock.Of<ILoggerFactory>());
		}

		protected internal virtual OrganizationCallbackDecorator CreateOrganizationCallbackDecorator(ILoggerFactory loggerFactory)
		{
			return this.CreateOrganizationCallbackDecorator(new ExtendedAuthenticationOptions(), loggerFactory);
		}

		protected internal virtual OrganizationCallbackDecorator CreateOrganizationCallbackDecorator(ExtendedAuthenticationOptions authenticationOptions, ILoggerFactory loggerFactory)
		{
			var configuration = Mock.Of<IConfiguration>();

			var options = Options.Create(authenticationOptions);

			var optionsMonitorMock = new Mock<IOptionsMonitor<ExtendedAuthenticationOptions>>();
			optionsMonitorMock.Setup(optionsMonitor => optionsMonitor.CurrentValue).Returns(authenticationOptions);
			var optionsMonitor = optionsMonitorMock.Object;

			return new OrganizationCallbackDecorator(new ActiveDirectory(configuration, new LdapConnectionStringParser(), loggerFactory, optionsMonitor), options, loggerFactory);
		}

		[TestMethod]
		public void DecorateAsync_Test()
		{
			const string authenticationScheme = "Organization";

			var serviceProvider = this.ConfigureServices("Organization-Callback-Decorator");
			var authenticationOptions = serviceProvider.GetRequiredService<IOptions<ExtendedAuthenticationOptions>>().Value;

			Assert.AreEqual(200, authenticationOptions.CallbackDecorators.ElementAt(1).Value.AuthenticationSchemes.First().Value);

			var organizationCallbackDecorator = (OrganizationCallbackDecorator)serviceProvider.GetRequiredService<IDecorationLoader>().GetCallbackDecoratorsAsync(authenticationScheme).Result.ElementAt(1);

			Assert.IsNotNull(organizationCallbackDecorator);
			Assert.AreEqual("organizationIdentity", organizationCallbackDecorator.IdentityClaimType);
			Assert.AreEqual("AB0123456789-", organizationCallbackDecorator.IdentityPrefix);

			var identity = organizationCallbackDecorator.IdentityPrefix;
			var identityNameParts = WindowsIdentity.GetCurrent().Name.Split('\\', 2).ToArray();
			if(identityNameParts.Length == 2)
				identity += identityNameParts[1];

			var claims = new ClaimBuilderCollection();
			var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("organizationIdentity", identity) }, "Test"));
			var authenticateResult = this.CreateAuthenticateResult(principal);

			organizationCallbackDecorator.DecorateAsync(authenticateResult, authenticationScheme, claims, null).Wait();

			Assert.AreEqual(2, claims.Count);
		}

		[TestMethod]
		public void DecorateAsync_WithoutOptions_Test()
		{
			const string authenticationScheme = "Organization";

			var serviceProvider = this.ConfigureServices("Organization-Callback-Decorator-Without-Options");
			var authenticationOptions = serviceProvider.GetRequiredService<IOptions<ExtendedAuthenticationOptions>>().Value;

			Assert.AreEqual(200, authenticationOptions.CallbackDecorators.ElementAt(1).Value.AuthenticationSchemes.First().Value);

			var organizationCallbackDecorator = (OrganizationCallbackDecorator)serviceProvider.GetRequiredService<IDecorationLoader>().GetCallbackDecoratorsAsync(authenticationScheme).Result.ElementAt(1);

			Assert.IsNotNull(organizationCallbackDecorator);
			Assert.IsNull(organizationCallbackDecorator.IdentityClaimType);
			Assert.IsNull(organizationCallbackDecorator.IdentityPrefix);

			var identity = organizationCallbackDecorator.IdentityPrefix;
			var identityNameParts = WindowsIdentity.GetCurrent().Name.Split('\\', 2).ToArray();
			if(identityNameParts.Length == 2)
				identity += identityNameParts[1];

			var claims = new ClaimBuilderCollection();
			var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("organizationIdentity", identity) }, "Test"));
			var authenticateResult = this.CreateAuthenticateResult(principal);

			organizationCallbackDecorator.DecorateAsync(authenticateResult, authenticationScheme, claims, null).Wait();

			Assert.AreEqual(0, claims.Count);
		}

		#endregion
	}
}