using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Decoration;
using TestHelpers.Mocks.Logging;

namespace UnitTests.Decoration
{
	[TestClass]
	public class IncludeClaimDecoratorTest : DecoratorTestBase
	{
		#region Methods

		protected internal virtual async Task<IncludeClaimDecorator> CreateDecoratorAsync(string fileName, ILoggerFactory loggerFactory)
		{
			var decorator = new IncludeClaimDecorator(loggerFactory);

			var configuration = await this.CreateConfigurationAsync(fileName);

			await decorator.InitializeAsync(configuration);

			return await Task.FromResult(decorator);
		}

		[TestMethod]
		public async Task DecorateAsync_ClaimsWithClaimTypePatterns_ShouldWorkProperly()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = JwtClaimTypes.Email, Value = "Email" },
				new ClaimBuilder { Type = JwtClaimTypes.GivenName, Value = "Given name" },
				new ClaimBuilder { Type = JwtClaimTypes.Name, Value = "Name" },
				new ClaimBuilder { Type = JwtClaimTypes.Subject, Value = "Subject" },
			};

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync());

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("Options-1", loggerFactory);

				decorator.PrincipalClaimsAsSource = false;

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.AreEqual(2, claims.Count);

				var claim = claims.First();
				Assert.AreEqual(JwtClaimTypes.Name, claim.Type);
				Assert.AreEqual("Name", claim.Value);

				claim = claims.ElementAt(1);
				Assert.AreEqual(JwtClaimTypes.Subject, claim.Type);
				Assert.AreEqual("Subject", claim.Value);

				Assert.AreEqual(5, loggerFactory.Logs.Count());

				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Starting filtering with the following patterns: \"name\", \"sub\"", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"email\" will NOT be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(2);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"given_name\" will NOT be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(3);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"name\" will be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(4);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"sub\" will be included.", log.Message);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_ClaimsWithWildcardPattern_ShouldWorkProperly()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = JwtClaimTypes.Email, Value = "Email" },
				new ClaimBuilder { Type = JwtClaimTypes.GivenName, Value = "Given name" },
				new ClaimBuilder { Type = JwtClaimTypes.Name, Value = "Name" },
				new ClaimBuilder { Type = JwtClaimTypes.Subject, Value = "Subject" },
			};

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync());

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = new IncludeClaimDecorator(loggerFactory)
				{
					PrincipalClaimsAsSource = false
				};

				decorator.Patterns.Add("*");

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.AreEqual(4, claims.Count);

				var claim = claims.First();
				Assert.AreEqual(JwtClaimTypes.Email, claim.Type);
				Assert.AreEqual("Email", claim.Value);

				claim = claims.ElementAt(1);
				Assert.AreEqual(JwtClaimTypes.GivenName, claim.Type);
				Assert.AreEqual("Given name", claim.Value);

				claim = claims.ElementAt(2);
				Assert.AreEqual(JwtClaimTypes.Name, claim.Type);
				Assert.AreEqual("Name", claim.Value);

				claim = claims.ElementAt(3);
				Assert.AreEqual(JwtClaimTypes.Subject, claim.Type);
				Assert.AreEqual("Subject", claim.Value);

				Assert.AreEqual(5, loggerFactory.Logs.Count());

				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Starting filtering with the following patterns: \"*\"", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"email\" will be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(2);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"given_name\" will be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(3);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"name\" will be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(4);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"sub\" will be included.", log.Message);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_MultipleClaimsWithSameType_ShouldWorkProperly()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = "claim_1", Value = "1" },
				new ClaimBuilder { Type = "claim_1", Value = "2" },
				new ClaimBuilder { Type = "claim_1", Value = "3" },
				new ClaimBuilder { Type = "claim_1", Value = "4" },
				new ClaimBuilder { Type = "claim_2", Value = "1" },
				new ClaimBuilder { Type = "claim_2", Value = "2" },
				new ClaimBuilder { Type = "claim_2", Value = "3" },
				new ClaimBuilder { Type = "claim_2", Value = "4" }
			};

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync());

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = new IncludeClaimDecorator(loggerFactory)
				{
					Patterns = { "claim_1" },
					PrincipalClaimsAsSource = false
				};

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.AreEqual(4, claims.Count);
				Assert.AreEqual(4, claims.Count(claim => claim.Type == "claim_1"));
			}
		}

		[TestMethod]
		public async Task DecorateAsync_MultiplePrincipalClaimsWithSameType_ShouldWorkProperly()
		{
			var claims = new ClaimBuilderCollection();
			var principalClaims = new List<Claim>
			{
				new("claim_1", "1"),
				new("claim_1", "2"),
				new("claim_1", "3"),
				new("claim_1", "4"),
				new("claim_2", "1"),
				new("claim_2", "2"),
				new("claim_2", "3"),
				new("claim_2", "4")
			};

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(null, null, principalClaims));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = new IncludeClaimDecorator(loggerFactory)
				{
					Patterns = { "claim_1" },
					PrincipalClaimsAsSource = true
				};

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.AreEqual(4, claims.Count);
				Assert.AreEqual(4, claims.Count(claim => claim.Type == "claim_1"));
			}
		}

		[TestMethod]
		public async Task DecorateAsync_PrincipalClaimsWithClaimTypePatterns_ShouldWorkProperly()
		{
			var claims = new ClaimBuilderCollection();
			var principalClaims = new List<Claim>
			{
				new(JwtClaimTypes.Email, "Email"),
				new(JwtClaimTypes.GivenName, "Given name"),
				new(JwtClaimTypes.Name, "Name"),
				new(JwtClaimTypes.Subject, "Subject")
			};

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(null, null, principalClaims));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("Options-1", loggerFactory);

				decorator.PrincipalClaimsAsSource = true;

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.AreEqual(2, claims.Count);

				var claim = claims.First();
				Assert.AreEqual(JwtClaimTypes.Name, claim.Type);
				Assert.AreEqual("Name", claim.Value);

				claim = claims.ElementAt(1);
				Assert.AreEqual(JwtClaimTypes.Subject, claim.Type);
				Assert.AreEqual("Subject", claim.Value);

				Assert.AreEqual(5, loggerFactory.Logs.Count());

				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Starting filtering with the following patterns: \"name\", \"sub\"", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"email\" will NOT be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(2);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"given_name\" will NOT be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(3);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"name\" will be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(4);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"sub\" will be included.", log.Message);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_PrincipalClaimsWithWildcardPattern_ShouldWorkProperly()
		{
			var claims = new ClaimBuilderCollection();
			var principalClaims = new List<Claim>
			{
				new(JwtClaimTypes.Email, "Email"),
				new(JwtClaimTypes.GivenName, "Given name"),
				new(JwtClaimTypes.Name, "Name"),
				new(JwtClaimTypes.Subject, "Subject")
			};

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(null, null, principalClaims));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = new IncludeClaimDecorator(loggerFactory)
				{
					PrincipalClaimsAsSource = true
				};

				decorator.Patterns.Add("*");

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.AreEqual(4, claims.Count);

				var claim = claims.First();
				Assert.AreEqual(JwtClaimTypes.Email, claim.Type);
				Assert.AreEqual("Email", claim.Value);

				claim = claims.ElementAt(1);
				Assert.AreEqual(JwtClaimTypes.GivenName, claim.Type);
				Assert.AreEqual("Given name", claim.Value);

				claim = claims.ElementAt(2);
				Assert.AreEqual(JwtClaimTypes.Name, claim.Type);
				Assert.AreEqual("Name", claim.Value);

				claim = claims.ElementAt(3);
				Assert.AreEqual(JwtClaimTypes.Subject, claim.Type);
				Assert.AreEqual("Subject", claim.Value);

				Assert.AreEqual(5, loggerFactory.Logs.Count());

				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Starting filtering with the following patterns: \"*\"", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"email\" will be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(2);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"given_name\" will be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(3);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"name\" will be included.", log.Message);

				log = loggerFactory.Logs.ElementAt(4);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"sub\" will be included.", log.Message);
			}
		}

		[TestMethod]
		public async Task PrincipalClaimsAsSource_ShouldReturnFalseByDefault()
		{
			await Task.CompletedTask;

			Assert.IsFalse(new ExcludeClaimDecorator(Mock.Of<ILoggerFactory>()).PrincipalClaimsAsSource);
		}

		#endregion
	}
}