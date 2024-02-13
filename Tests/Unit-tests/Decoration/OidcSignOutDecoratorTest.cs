using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Decoration;
using TestHelpers.Mocks.Logging;

namespace UnitTests.Decoration
{
	[TestClass]
	public class OidcSignOutDecoratorTest : DecoratorTestBase
	{
		#region Methods

		[TestMethod]
		public async Task DecorateAsync_IfAnIdentityTokenAndASessionIdClaimExists_ShouldWorkProperly()
		{
			const string expectedIdentityProvider = "Test-authentication-sheme";
			const string expectedIdToken = "Id-token value";
			const string expectedSessionId = "Session-id value";

			var sourceAuthenticationProperties = new AuthenticationProperties();
			sourceAuthenticationProperties.StoreTokens(new[] { new AuthenticationToken { Name = OidcConstants.TokenTypes.IdentityToken, Value = expectedIdToken } });

			var sourceClaims = new List<Claim>
			{
				new(JwtClaimTypes.SessionId, expectedSessionId)
			};

			var sourceAuthenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(sourceAuthenticationProperties, expectedIdentityProvider, sourceClaims));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var authenticationProperties = new AuthenticationProperties();
				var claims = new ClaimBuilderCollection();
				var decorator = new OidcSignOutDecorator(loggerFactory);

				await decorator.DecorateAsync(sourceAuthenticateResult, sourceAuthenticateResult.Ticket.AuthenticationScheme, claims, authenticationProperties);

				var identityProvider = claims.FirstOrDefault(claim => string.Equals(decorator.IdentityProviderClaimType, claim.Type, StringComparison.OrdinalIgnoreCase))?.Value;
				Assert.AreEqual(expectedIdentityProvider, identityProvider);

				var idToken = authenticationProperties.GetTokenValue(OidcConstants.TokenTypes.IdentityToken);
				Assert.AreEqual(expectedIdToken, idToken);

				var sessionId = claims.FirstOrDefault(claim => string.Equals(decorator.SessionIdClaimType, claim.Type, StringComparison.OrdinalIgnoreCase))?.Value;
				Assert.AreEqual(expectedSessionId, sessionId);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_IfNeitherAnIdentityTokenNorASessionIdClaimExists_ShouldWorkProperly()
		{
			const string expectedIdentityProvider = "Test-authentication-sheme";

			var sourceAuthenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(new AuthenticationProperties(), expectedIdentityProvider, new List<Claim>()));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var authenticationProperties = new AuthenticationProperties();
				var claims = new ClaimBuilderCollection();
				var decorator = new OidcSignOutDecorator(loggerFactory);

				await decorator.DecorateAsync(sourceAuthenticateResult, sourceAuthenticateResult.Ticket.AuthenticationScheme, claims, authenticationProperties);

				var identityProvider = claims.FirstOrDefault(claim => string.Equals(decorator.IdentityProviderClaimType, claim.Type, StringComparison.OrdinalIgnoreCase))?.Value;
				Assert.AreEqual(expectedIdentityProvider, identityProvider);

				Assert.IsNull(authenticationProperties.GetTokenValue(OidcConstants.TokenTypes.IdentityToken));

				Assert.IsNull(claims.FirstOrDefault(claim => string.Equals(decorator.SessionIdClaimType, claim.Type, StringComparison.OrdinalIgnoreCase)));
			}
		}

		[TestMethod]
		public async Task DecorateAsync_IfOnlyAnIdentityTokenExists_ShouldWorkProperly()
		{
			const string expectedIdentityProvider = "Test-authentication-sheme";
			const string expectedIdToken = "Id-token value";

			var sourceAuthenticationProperties = new AuthenticationProperties();
			sourceAuthenticationProperties.StoreTokens(new[] { new AuthenticationToken { Name = OidcConstants.TokenTypes.IdentityToken, Value = expectedIdToken } });

			var sourceAuthenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(sourceAuthenticationProperties, expectedIdentityProvider, new List<Claim>()));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var authenticationProperties = new AuthenticationProperties();
				var claims = new ClaimBuilderCollection();
				var decorator = new OidcSignOutDecorator(loggerFactory);

				await decorator.DecorateAsync(sourceAuthenticateResult, sourceAuthenticateResult.Ticket.AuthenticationScheme, claims, authenticationProperties);

				var identityProvider = claims.FirstOrDefault(claim => string.Equals(decorator.IdentityProviderClaimType, claim.Type, StringComparison.OrdinalIgnoreCase))?.Value;
				Assert.AreEqual(expectedIdentityProvider, identityProvider);

				var idTokenValue = authenticationProperties.GetTokenValue(OidcConstants.TokenTypes.IdentityToken);
				Assert.AreEqual(expectedIdToken, idTokenValue);

				Assert.IsNull(claims.FirstOrDefault(claim => string.Equals(decorator.SessionIdClaimType, claim.Type, StringComparison.OrdinalIgnoreCase)));
			}
		}

		[TestMethod]
		public async Task DecorateAsync_IfOnlyASessionIdClaimExists_ShouldWorkProperly()
		{
			const string expectedIdentityProvider = "Test-authentication-sheme";
			const string expectedSessionId = "Session-id value";

			var sourceClaims = new List<Claim>
			{
				new(JwtClaimTypes.SessionId, expectedSessionId)
			};

			var sourceAuthenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(new AuthenticationProperties(), expectedIdentityProvider, sourceClaims));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var authenticationProperties = new AuthenticationProperties();
				var claims = new ClaimBuilderCollection();
				var decorator = new OidcSignOutDecorator(loggerFactory);

				await decorator.DecorateAsync(sourceAuthenticateResult, sourceAuthenticateResult.Ticket.AuthenticationScheme, claims, authenticationProperties);

				var identityProvider = claims.FirstOrDefault(claim => string.Equals(decorator.IdentityProviderClaimType, claim.Type, StringComparison.OrdinalIgnoreCase))?.Value;
				Assert.AreEqual(expectedIdentityProvider, identityProvider);

				Assert.IsNull(authenticationProperties.GetTokenValue(OidcConstants.TokenTypes.IdentityToken));

				var sessionId = claims.FirstOrDefault(claim => string.Equals(decorator.SessionIdClaimType, claim.Type, StringComparison.OrdinalIgnoreCase))?.Value;
				Assert.AreEqual(expectedSessionId, sessionId);
			}
		}

		[TestMethod]
		[ExpectedException(typeof(InvalidOperationException))]
		public async Task DecorateAsync_IfTheAuthencticationResultParameterIsNull_ShouldThrowAnInvalidOperationException()
		{
			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				try
				{
					await new OidcSignOutDecorator(loggerFactory).DecorateAsync(null, string.Empty, new ClaimBuilderCollection(), new AuthenticationProperties());
				}
				catch(InvalidOperationException invalidOperationException)
				{
					if(invalidOperationException.InnerException is ArgumentNullException { ParamName: "authenticateResult" })
						throw;
				}
			}
		}

		[TestMethod]
		public async Task DecorateAsync_IfTheAuthencticationSchemeParameterIsAnEmptyString_ShouldWorkProperly()
		{
			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var claims = new ClaimBuilderCollection();
				var decorator = new OidcSignOutDecorator(loggerFactory);

				await decorator.DecorateAsync(AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync()), string.Empty, claims, new AuthenticationProperties());

				Assert.AreEqual(1, claims.Count);

				var identityProviderClaims = claims.Where(claim => string.Equals(decorator.IdentityProviderClaimType, claim.Type, StringComparison.OrdinalIgnoreCase)).ToArray();
				Assert.AreEqual(1, identityProviderClaims.Length);

				var identityProviderClaim = identityProviderClaims.First();

				Assert.AreEqual(decorator.IdentityProviderClaimType, identityProviderClaim.Type);
				Assert.AreEqual(string.Empty, identityProviderClaim.Value);
			}
		}

		[TestMethod]
		[ExpectedException(typeof(InvalidOperationException))]
		public async Task DecorateAsync_IfTheAuthencticationSchemeParameterIsNull_ShouldThrowAnInvalidOperationException()
		{
			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				try
				{
					await new OidcSignOutDecorator(loggerFactory).DecorateAsync(AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync()), null, new ClaimBuilderCollection(), new AuthenticationProperties());
				}
				catch(InvalidOperationException invalidOperationException)
				{
					if(invalidOperationException.InnerException is ArgumentNullException { ParamName: "authenticationScheme" })
						throw;
				}
			}
		}

		[TestMethod]
		[ExpectedException(typeof(InvalidOperationException))]
		public async Task DecorateAsync_IfTheClaimsParameterIsNull_ShouldThrowAnInvalidOperationException()
		{
			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				try
				{
					await new OidcSignOutDecorator(loggerFactory).DecorateAsync(AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync()), string.Empty, null, new AuthenticationProperties());
				}
				catch(InvalidOperationException invalidOperationException)
				{
					if(invalidOperationException.InnerException is ArgumentNullException { ParamName: "claims" })
						throw;
				}
			}
		}

		[TestMethod]
		[ExpectedException(typeof(InvalidOperationException))]
		public async Task DecorateAsync_IfThePropertiesParameterIsNull_ShouldThrowAnInvalidOperationException()
		{
			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				try
				{
					await new OidcSignOutDecorator(loggerFactory).DecorateAsync(AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync()), string.Empty, new ClaimBuilderCollection(), null);
				}
				catch(InvalidOperationException invalidOperationException)
				{
					if(invalidOperationException.InnerException is ArgumentNullException { ParamName: "properties" })
						throw;
				}
			}
		}

		#endregion
	}
}