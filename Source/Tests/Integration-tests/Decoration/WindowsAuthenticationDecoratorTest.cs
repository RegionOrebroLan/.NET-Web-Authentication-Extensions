using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.Security.Claims;

namespace RegionOrebroLan.Web.Authentication.IntegrationTests.Decoration
{
	[TestClass]
	public class WindowsAuthenticationDecoratorTest
	{
		#region Methods

		protected internal virtual AuthenticateResult CreateAuthenticateResult(ClaimsPrincipal principal)
		{
			return AuthenticateResult.Success(new AuthenticationTicket(principal, "Ticket-authentication-scheme"));
		}

		protected internal virtual WindowsAuthenticationDecorator CreateWindowsAuthenticationDecorator()
		{
			return this.CreateWindowsAuthenticationDecorator(Mock.Of<ILoggerFactory>());
		}

		protected internal virtual WindowsAuthenticationDecorator CreateWindowsAuthenticationDecorator(ILoggerFactory loggerFactory)
		{
			return this.CreateWindowsAuthenticationDecorator(new ExtendedAuthenticationOptions(), loggerFactory);
		}

		protected internal virtual WindowsAuthenticationDecorator CreateWindowsAuthenticationDecorator(ExtendedAuthenticationOptions authenticationOptions, ILoggerFactory loggerFactory)
		{
			return new WindowsAuthenticationDecorator(Options.Create(authenticationOptions), loggerFactory);
		}

		[TestMethod]
		public void DecorateAsync_CurrentWindowsPrincipal_WithoutRoles_Test()
		{
			const string authenticationScheme = "Test-authentication-scheme";
			var claims = new ClaimBuilderCollection();
			var windowsIdentity = WindowsIdentity.GetCurrent();
			var principal = new WindowsPrincipal(windowsIdentity);
			var authenticateResult = this.CreateAuthenticateResult(principal);
			var windowsAuthenticationDecorator = this.CreateWindowsAuthenticationDecorator();

			windowsAuthenticationDecorator.DecorateAsync(authenticateResult, authenticationScheme, claims, null).Wait();

			Assert.AreEqual(6, claims.Count);
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
			var windowsAuthenticationDecorator = this.CreateWindowsAuthenticationDecorator(new ExtendedAuthenticationOptions {Windows = {IncludeRoleClaims = true}}, Mock.Of<ILoggerFactory>());

			windowsAuthenticationDecorator.DecorateAsync(authenticateResult, authenticationScheme, claims, null).Wait();

			// ReSharper disable PossibleNullReferenceException
			Assert.AreEqual(6 + windowsIdentity.Groups.Count, claims.Count);
			// ReSharper restore PossibleNullReferenceException
		}

		#endregion
	}
}