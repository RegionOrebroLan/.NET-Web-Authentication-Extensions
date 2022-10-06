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
	public class ExcludeClaimDecoratorTest : DecoratorTestBase
	{
		#region Methods

		protected internal virtual async Task<ExcludeClaimDecorator> CreateDecoratorAsync(string fileName, ILoggerFactory loggerFactory)
		{
			var decorator = new ExcludeClaimDecorator(loggerFactory);

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
				Assert.AreEqual("Starting filtering with the following patterns: \"email\", \"given_name\"", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"email\" will be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(2);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"given_name\" will be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(3);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"name\" will NOT be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(4);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"sub\" will NOT be excluded.", log.Message);
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
				new ClaimBuilder { Type = JwtClaimTypes.Subject, Value = "Subject" }
			};

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync());

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = new ExcludeClaimDecorator(loggerFactory)
				{
					PrincipalClaimsAsSource = false
				};

				decorator.Patterns.Add("*");

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.IsFalse(claims.Any());

				Assert.AreEqual(5, loggerFactory.Logs.Count());

				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Starting filtering with the following patterns: \"*\"", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"email\" will be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(2);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"given_name\" will be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(3);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"name\" will be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(4);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"sub\" will be excluded.", log.Message);
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
				Assert.AreEqual("Starting filtering with the following patterns: \"email\", \"given_name\"", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"email\" will be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(2);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"given_name\" will be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(3);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"name\" will NOT be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(4);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"sub\" will NOT be excluded.", log.Message);
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
				var decorator = new ExcludeClaimDecorator(loggerFactory)
				{
					PrincipalClaimsAsSource = true
				};

				decorator.Patterns.Add("*");

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.IsFalse(claims.Any());

				Assert.AreEqual(5, loggerFactory.Logs.Count());

				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Starting filtering with the following patterns: \"*\"", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"email\" will be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(2);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"given_name\" will be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(3);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"name\" will be excluded.", log.Message);

				log = loggerFactory.Logs.ElementAt(4);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Claim-type \"sub\" will be excluded.", log.Message);
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