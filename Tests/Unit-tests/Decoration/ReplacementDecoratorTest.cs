using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Decoration;
using TestHelpers.Mocks.Logging;

namespace UnitTests.Decoration
{
	[TestClass]
	public class ReplacementDecoratorTest : DecoratorTestBase
	{
		#region Methods

		protected internal virtual async Task<ReplacementDecorator> CreateDecoratorAsync(string fileName, ILoggerFactory loggerFactory)
		{
			var decorator = new ReplacementDecorator(loggerFactory);

			var configuration = await this.CreateConfigurationAsync(fileName);

			await decorator.InitializeAsync(configuration);

			return await Task.FromResult(decorator);
		}

		[TestMethod]
		public async Task DecorateAsync_Test1()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = ClaimTypes.Name, Value = "1" },
				new ClaimBuilder { Type = ClaimTypes.NameIdentifier, Value = "2" },
				new ClaimBuilder { Type = "claim_1_to_replace", Value = "3" },
				new ClaimBuilder { Type = "claim_2_to_replace", Value = "4" },
				new ClaimBuilder { Type = "claim_4_to_replace", Value = "5" },
				new ClaimBuilder { Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/test", Value = "7" }
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("Options-1", loggerFactory);

				decorator.Replacements.Add(ClaimTypes.Email, JwtClaimTypes.Email);

				await decorator.DecorateAsync(null, null, claims, null);

				Assert.AreEqual(6, claims.Count);

				var claim = claims.First();
				Assert.AreEqual("name", claim.Type);
				Assert.AreEqual("1", claim.Value);

				claim = claims.ElementAt(1);
				Assert.AreEqual("sub", claim.Type);
				Assert.AreEqual("2", claim.Value);

				claim = claims.ElementAt(2);
				Assert.AreEqual("claim_1", claim.Type);
				Assert.AreEqual("3", claim.Value);

				claim = claims.ElementAt(3);
				Assert.AreEqual("claim_2", claim.Type);
				Assert.AreEqual("4", claim.Value);

				claim = claims.ElementAt(4);
				Assert.AreEqual("claim_4_to_replace", claim.Type);
				Assert.AreEqual("5", claim.Value);

				Assert.AreEqual(6, loggerFactory.Logs.Count());

				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Replacing claim-type \"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\" with claim-type \"name\".", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Replacing claim-type \"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier\" with claim-type \"sub\".", log.Message);

				log = loggerFactory.Logs.ElementAt(2);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Replacing claim-type \"claim_1_to_replace\" with claim-type \"claim_1\".", log.Message);

				log = loggerFactory.Logs.ElementAt(3);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Replacing claim-type \"claim_2_to_replace\" with claim-type \"claim_2\".", log.Message);

				log = loggerFactory.Logs.ElementAt(4);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Skipping claim-type \"claim_4_to_replace\". The replacements does not contain \"claim_4_to_replace\" as key.", log.Message);

				log = loggerFactory.Logs.ElementAt(5);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("Skipping claim-type \"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/test\". The replacements contains neither \"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/test\" nor \"http%3a//schemas.xmlsoap.org/ws/2005/05/identity/claims/test\" as key.", log.Message);
			}
		}

		#endregion
	}
}