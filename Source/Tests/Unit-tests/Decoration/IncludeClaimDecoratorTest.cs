using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.Test.Mocks.Logging;

namespace RegionOrebroLan.Web.Authentication.UnitTests.Decoration
{
	[TestClass]
	public class IncludeClaimDecoratorTest
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

		protected internal virtual IncludeClaimDecorator CreateIncludeClaimDecorator()
		{
			return this.CreateIncludeClaimDecorator(Mock.Of<ILoggerFactory>());
		}

		protected internal virtual IncludeClaimDecorator CreateIncludeClaimDecorator(ILoggerFactory loggerFactory)
		{
			return new Mock<IncludeClaimDecorator>(loggerFactory) {CallBase = true}.Object;
		}

		[TestMethod]
		public void GetSourceClaim_IfThePrincipalParameterContainsAClaimWithTheSourceAsClaimType_ShouldReturnTheClaim()
		{
			const string claimType = "Test";
			var includeClaimDecorator = this.CreateIncludeClaimDecorator();

			var claim = includeClaimDecorator.GetSourceClaim(new ClaimsPrincipal(new ClaimsIdentity(new[] {new Claim(claimType, string.Empty),})), claimType);

			Assert.AreEqual(claimType, claim.Type);
		}

		[TestMethod]
		public void GetSourceClaim_IfThePrincipalParameterDoesNotContainAClaimWithTheSourceAsClaimType_ShouldReturnNull()
		{
			// ReSharper disable ConvertToUsingDeclaration
			using(var loggerFactory = new LoggerFactoryMock())
			{
				const string claimType = "Test";
				var includeClaimDecorator = this.CreateIncludeClaimDecorator(loggerFactory);

				var claim = includeClaimDecorator.GetSourceClaim(new ClaimsPrincipal(new ClaimsIdentity(new[] {new Claim(claimType, string.Empty),})), "Another");

				Assert.IsNull(claim);
			}
			// ReSharper restore ConvertToUsingDeclaration
		}

		[TestMethod]
		public void TryGetSpecialSourceClaim_PrincipalIdentityAuthenticationType_Test()
		{
			const string authenticationType = "Test-authentication-type";
			var includeClaimDecorator = this.CreateIncludeClaimDecorator();
			var principal = new ClaimsPrincipal(new ClaimsIdentity(null, authenticationType));
			const string source = "Principal.Identity.AuthenticationType";

			Assert.IsTrue(includeClaimDecorator.TryGetSpecialSourceClaim(principal, source, out var claim));
			Assert.AreEqual(source, claim.Type);
			Assert.AreEqual(authenticationType, claim.Value);
		}

		#endregion
	}
}