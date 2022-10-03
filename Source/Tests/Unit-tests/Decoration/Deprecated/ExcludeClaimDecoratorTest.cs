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

namespace UnitTests.Decoration.Deprecated
{
	[TestClass]
	public class ExcludeClaimDecoratorTest
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

		protected internal virtual ExcludeClaimDecorator CreateExcludeClaimDecorator()
		{
			return this.CreateExcludeClaimDecorator(Mock.Of<ILoggerFactory>());
		}

		protected internal virtual ExcludeClaimDecorator CreateExcludeClaimDecorator(ILoggerFactory loggerFactory)
		{
			return new Mock<ExcludeClaimDecorator>(loggerFactory) {CallBase = true}.Object;
		}

		[TestMethod]
		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		public void DecorateAsync_IfThePropertiesParameterIsNull_ShouldNotThrowAnException()
		{
			var excludeClaimDecorator = this.CreateExcludeClaimDecorator();

			try
			{
				excludeClaimDecorator.DecorateAsync(this.CreateAuthenticateResult(), "Test", new ClaimBuilderCollection(), null).Wait();
			}
			catch
			{
				Assert.Fail("Should not throw an exception.");
			}
		}

		[TestMethod]
		public void DecorateAsync_ShouldExcludeClaimsProperly()
		{
			var claims = new ClaimBuilderCollection
			{
				{"A-type", "A-value"},
				{"B-type", "B-value"},
				{"C-type", "C-value"},
				{"D-type", "D-value"},
				{"E-type", "E-value"}
			};
			var authenticateResult = this.CreateAuthenticateResult(new ClaimsPrincipal(new ClaimsIdentity(claims.Build())));
			var excludeClaimDecorator = this.CreateExcludeClaimDecorator();
			excludeClaimDecorator.IncludeAuthenticationSchemeAsIdentityProviderClaim = false;
			excludeClaimDecorator.ClaimTypeExclusions.Add("A-type");
			excludeClaimDecorator.ClaimTypeExclusions.Add("C-type");
			excludeClaimDecorator.ClaimTypeExclusions.Add("E-type");

			claims.Clear();

			Assert.AreEqual(0, claims.Count);

			excludeClaimDecorator.DecorateAsync(authenticateResult, "Test", claims, null).Wait();

			Assert.AreEqual(2, claims.Count);
			Assert.IsNotNull(claims.FirstOrDefault(claim => claim.Type == "B-type"));
			Assert.IsNotNull(claims.FirstOrDefault(claim => claim.Type == "D-type"));
		}

		[TestMethod]
		public void DecorateAsync_ShouldIncludeAllPrincipalClaimsByDefault()
		{
			var claims = new ClaimBuilderCollection
			{
				{"A-type", "A-value"},
				{"B-type", "B-value"},
				{"C-type", "C-value"}
			};
			var authenticateResult = this.CreateAuthenticateResult(new ClaimsPrincipal(new ClaimsIdentity(claims.Build())));
			var excludeClaimDecorator = this.CreateExcludeClaimDecorator();
			excludeClaimDecorator.IncludeAuthenticationSchemeAsIdentityProviderClaim = false;

			claims.Clear();

			Assert.AreEqual(0, claims.Count);

			excludeClaimDecorator.DecorateAsync(authenticateResult, "Test", claims, null).Wait();

			Assert.AreEqual(3, claims.Count);
		}

		#endregion
	}
}