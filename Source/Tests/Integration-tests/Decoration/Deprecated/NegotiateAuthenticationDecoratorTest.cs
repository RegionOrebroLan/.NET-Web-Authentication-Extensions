using System;
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
using RegionOrebroLan.Web.Authentication.Decoration.Deprecated;
using RegionOrebroLan.Web.Authentication.DirectoryServices;
using RegionOrebroLan.Web.Authentication.Security.Claims;

namespace IntegrationTests.Decoration.Deprecated
{
	[TestClass]
	public class NegotiateAuthenticationDecoratorTest : AuthenticationDecoratorTestBase
	{
		#region Methods

		protected internal virtual AuthenticateResult CreateAuthenticateResult(ClaimsPrincipal principal)
		{
			return AuthenticateResult.Success(new AuthenticationTicket(principal, "Ticket-authentication-scheme"));
		}

		protected internal virtual ILoggerFactory CreateLoggerFactory()
		{
			var loggerFactoryMock = new Mock<ILoggerFactory>();
			loggerFactoryMock.Setup(loggerFactory => loggerFactory.CreateLogger(It.IsAny<string>())).Returns(Mock.Of<ILogger>());
			return loggerFactoryMock.Object;
		}

		protected internal virtual NegotiateAuthenticationDecorator CreateNegotiateAuthenticationDecorator()
		{
			return this.CreateNegotiateAuthenticationDecorator(this.CreateLoggerFactory());
		}

		protected internal virtual NegotiateAuthenticationDecorator CreateNegotiateAuthenticationDecorator(ILoggerFactory loggerFactory)
		{
			return this.CreateNegotiateAuthenticationDecorator(new ExtendedAuthenticationOptions(), loggerFactory);
		}

		protected internal virtual NegotiateAuthenticationDecorator CreateNegotiateAuthenticationDecorator(ExtendedAuthenticationOptions authenticationOptions, ILoggerFactory loggerFactory)
		{
			var configuration = Mock.Of<IConfiguration>();

			var authenticationOptionsMonitorMock = new Mock<IOptionsMonitor<ExtendedAuthenticationOptions>>();
			authenticationOptionsMonitorMock.Setup(optionsMonitor => optionsMonitor.CurrentValue).Returns(authenticationOptions);
			var authenticationOptionsMonitor = authenticationOptionsMonitorMock.Object;

			return new NegotiateAuthenticationDecorator(new ActiveDirectory(configuration, new LdapConnectionStringParser(), loggerFactory, authenticationOptionsMonitor), authenticationOptionsMonitor, loggerFactory);
		}

		[TestMethod]
		public void DecorateAsync_CurrentWindowsPrincipal_WithoutRoles_Test()
		{
			const string authenticationScheme = "Test-authentication-scheme";
			var claims = new ClaimBuilderCollection();
			var windowsIdentity = WindowsIdentity.GetCurrent();
			var principal = new WindowsPrincipal(windowsIdentity);
			var authenticateResult = this.CreateAuthenticateResult(principal);
			var negotiateAuthenticationDecorator = this.CreateNegotiateAuthenticationDecorator();

			negotiateAuthenticationDecorator.DecorateAsync(authenticateResult, authenticationScheme, claims, null).Wait();

			Assert.AreEqual(8, claims.Count);
			Assert.AreEqual(windowsIdentity.AuthenticationType, claims.First(claim => string.Equals(claim.Type, ClaimTypes.AuthenticationMethod, StringComparison.Ordinal)).Value);
			Assert.AreEqual(windowsIdentity.Name, claims.First(claim => string.Equals(claim.Type, ClaimTypes.Name, StringComparison.Ordinal)).Value);
			Assert.AreEqual(windowsIdentity.FindFirst(ClaimTypes.PrimarySid).Value, claims.First(claim => string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal)).Value);
			Assert.AreEqual(windowsIdentity.FindFirst(ClaimTypes.PrimarySid).Value, claims.First(claim => string.Equals(claim.Type, ClaimTypes.PrimarySid, StringComparison.Ordinal)).Value);
			Assert.AreEqual(windowsIdentity.Name, claims.First(claim => string.Equals(claim.Type, ClaimTypes.WindowsAccountName, StringComparison.Ordinal)).Value);
			Assert.AreEqual(authenticationScheme, claims.First(claim => string.Equals(claim.Type, ExtendedClaimTypes.IdentityProvider, StringComparison.Ordinal)).Value);
		}

		[TestMethod]
		public void DecorateAsync_CurrentWindowsPrincipal_WithRoles_Test()
		{
			const string authenticationScheme = "Test-authentication-scheme";
			var claims = new ClaimBuilderCollection();
			var windowsIdentity = WindowsIdentity.GetCurrent();
			var principal = new WindowsPrincipal(windowsIdentity);
			var authenticateResult = this.CreateAuthenticateResult(principal);
			var negotiateAuthenticationDecorator = this.CreateNegotiateAuthenticationDecorator(new ExtendedAuthenticationOptions { Negotiate = { IncludeRoleClaims = true } }, this.CreateLoggerFactory());

			negotiateAuthenticationDecorator.DecorateAsync(authenticateResult, authenticationScheme, claims, null).Wait();

			// ReSharper disable PossibleNullReferenceException
			Assert.AreEqual(8 + windowsIdentity.Groups.Count, claims.Count);
			// ReSharper restore PossibleNullReferenceException
		}

		[TestMethod]
		public void OverrideOptionsWithConfiguration_Remove_Test()
		{
			var serviceProvider = this.ConfigureServices("Negotiate-Decorator-Remove");
			var authenticationOptions = serviceProvider.GetRequiredService<IOptions<ExtendedAuthenticationOptions>>().Value;

			Assert.AreEqual(444, authenticationOptions.AuthenticationDecorators.First().Value.AuthenticationSchemes.First().Value);

			var negotiateAuthenticationDecorator = (NegotiateAuthenticationDecorator)serviceProvider.GetRequiredService<IDecorationLoader>().GetAuthenticationDecoratorsAsync("Negotiate").Result.First();

			Assert.IsNotNull(negotiateAuthenticationDecorator);
			Assert.IsNotNull(negotiateAuthenticationDecorator.ClaimInclusionsMap);
			Assert.AreEqual(7, negotiateAuthenticationDecorator.ClaimInclusionsMap.Count);

			var claims = new ClaimBuilderCollection();
			var windowsIdentity = WindowsIdentity.GetCurrent();
			var principal = new WindowsPrincipal(windowsIdentity);
			var authenticateResult = this.CreateAuthenticateResult(principal);

			negotiateAuthenticationDecorator.DecorateAsync(authenticateResult, "Negotiate", claims, null).Wait();

			Assert.AreEqual(1, claims.Count);
		}

		[TestMethod]
		public void OverrideOptionsWithConfiguration_Test()
		{
			var serviceProvider = this.ConfigureServices("Negotiate-Decorator-Change");
			var authenticationOptions = serviceProvider.GetRequiredService<IOptions<ExtendedAuthenticationOptions>>().Value;

			Assert.AreEqual(54, authenticationOptions.AuthenticationDecorators.First().Value.AuthenticationSchemes.First().Value);

			var negotiateAuthenticationDecorator = (NegotiateAuthenticationDecorator)serviceProvider.GetRequiredService<IDecorationLoader>().GetAuthenticationDecoratorsAsync("Negotiate").Result.First();

			Assert.IsNotNull(negotiateAuthenticationDecorator);
			Assert.AreEqual(string.Empty, negotiateAuthenticationDecorator.ClaimInclusionsMap["AuthenticationMethod"].Source);
			Assert.AreEqual(string.Empty, negotiateAuthenticationDecorator.ClaimInclusionsMap["Name"].Source);
			Assert.AreEqual(" ", negotiateAuthenticationDecorator.ClaimInclusionsMap["NameIdentifier"].Source);
		}

		#endregion
	}
}