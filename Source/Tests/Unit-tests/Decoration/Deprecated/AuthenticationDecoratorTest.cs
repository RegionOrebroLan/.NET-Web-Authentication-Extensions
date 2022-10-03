using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Security.Claims.Extensions;
using RegionOrebroLan.Web.Authentication.Decoration.Deprecated;
using RegionOrebroLan.Web.Authentication.Security.Claims;

namespace UnitTests.Decoration.Deprecated
{
	[TestClass]
	public class AuthenticationDecoratorTest
	{
		#region Methods

		protected internal virtual AuthenticateResult CreateAuthenticateResult()
		{
			return this.CreateAuthenticateResult(new ClaimsPrincipal());
		}

		protected internal virtual AuthenticateResult CreateAuthenticateResult(ClaimsPrincipal principal)
		{
			return AuthenticateResult.Success(new AuthenticationTicket(principal, "Ticket-authentication-scheme"));
		}

		protected internal virtual AuthenticationDecorator CreateAuthenticationDecorator()
		{
			return this.CreateAuthenticationDecorator(Mock.Of<ILoggerFactory>());
		}

		protected internal virtual AuthenticationDecorator CreateAuthenticationDecorator(ILoggerFactory loggerFactory)
		{
			return new Mock<AuthenticationDecorator>(loggerFactory) { CallBase = true }.Object;
		}

		[TestMethod]
		public void DecorateAsync_IfIncludeAuthenticationSchemeAsIdentityProviderClaim_And_IfTheClaimAlreadyExists_ShouldNotAddTheClaim()
		{
			const string authenticationScheme = "Authentication-scheme";
			var authenticationDecorator = this.CreateAuthenticationDecorator();
			var claims = new ClaimBuilderCollection
			{
				{ ExtendedClaimTypes.IdentityProvider, authenticationScheme }
			};

			Assert.AreEqual(1, claims.Count);

			authenticationDecorator.DecorateAsync(null, authenticationScheme, claims, null).Wait();

			Assert.AreEqual(1, claims.Count);
		}

		[TestMethod]
		public void DecorateAsync_IfIncludeAuthenticationSchemeAsIdentityProviderClaim_And_IfTheClaimNotAlreadyExists_ShouldAddTheClaim()
		{
			const string authenticationScheme = "Authentication-scheme";
			var authenticationDecorator = this.CreateAuthenticationDecorator();
			var claims = new ClaimBuilderCollection();

			authenticationDecorator.DecorateAsync(null, authenticationScheme, claims, null).Wait();

			Assert.AreEqual(authenticationScheme, claims.First(claim => string.Equals(ExtendedClaimTypes.IdentityProvider, claim.Type, StringComparison.OrdinalIgnoreCase)).Value);
		}

		[TestMethod]
		public void DecorateAsync_IfIncludeAuthenticationSchemeAsIdentityProviderClaimIsFalse_ShouldNotAddTheClaim()
		{
			const string authenticationScheme = "Authentication-scheme";
			var authenticationDecorator = this.CreateAuthenticationDecorator();
			var claims = new ClaimBuilderCollection();

			authenticationDecorator.IncludeAuthenticationSchemeAsIdentityProviderClaim = false;

			authenticationDecorator.DecorateAsync(null, authenticationScheme, claims, null).Wait();

			Assert.IsFalse(claims.Any());
		}

		[TestMethod]
		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		public void DecorateAsync_IfTheAuthenticateResultParameterIsNull_ShouldNotThrowAnException()
		{
			var authenticationDecorator = this.CreateAuthenticationDecorator();

			try
			{
				authenticationDecorator.DecorateAsync(null, "Test", new ClaimBuilderCollection(), new AuthenticationProperties()).Wait();
			}
			catch
			{
				Assert.Fail("Should not throw an exception.");
			}
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentNullException))]
		public void DecorateAsync_IfTheAuthenticationSchemeParameterIsNull_ShouldThrowAnArgumentNullException()
		{
			var authenticationDecorator = this.CreateAuthenticationDecorator();

			try
			{
				authenticationDecorator.DecorateAsync(this.CreateAuthenticateResult(), null, new ClaimBuilderCollection(), new AuthenticationProperties()).Wait();
			}
			catch(AggregateException aggregateException)
			{
				if(aggregateException.InnerExceptions.FirstOrDefault() is ArgumentNullException argumentNullException && string.Equals(argumentNullException.ParamName, "authenticationScheme", StringComparison.Ordinal))
					throw argumentNullException;
			}
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentNullException))]
		public void DecorateAsync_IfTheClaimsParameterIsNull_ShouldThrowAnArgumentNullException()
		{
			var authenticationDecorator = this.CreateAuthenticationDecorator();

			try
			{
				authenticationDecorator.DecorateAsync(this.CreateAuthenticateResult(), "Test", null, new AuthenticationProperties()).Wait();
			}
			catch(AggregateException aggregateException)
			{
				if(aggregateException.InnerExceptions.FirstOrDefault() is ArgumentNullException argumentNullException && string.Equals(argumentNullException.ParamName, "claims", StringComparison.Ordinal))
					throw argumentNullException;
			}
		}

		[TestMethod]
		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		public void DecorateAsync_IfThePropertiesParameterIsNull_ShouldNotThrowAnException()
		{
			var authenticationDecorator = this.CreateAuthenticationDecorator();

			try
			{
				authenticationDecorator.DecorateAsync(this.CreateAuthenticateResult(), "Test", new ClaimBuilderCollection(), null).Wait();
			}
			catch
			{
				Assert.Fail("Should not throw an exception.");
			}
		}

		#endregion
	}
}