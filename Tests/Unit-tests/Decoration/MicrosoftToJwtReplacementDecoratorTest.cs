using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.Extensions;
using TestHelpers.Mocks.Logging;

namespace UnitTests.Decoration
{
	[TestClass]
	public class MicrosoftToJwtReplacementDecoratorTest : DecoratorTestBase
	{
		#region Methods

		protected internal virtual async Task<MicrosoftToJwtReplacementDecorator> CreateDecoratorAsync(string fileName, ILoggerFactory loggerFactory)
		{
			var decorator = new MicrosoftToJwtReplacementDecorator(loggerFactory);

			var configuration = await this.CreateConfigurationAsync(fileName);

			await decorator.InitializeAsync(configuration);

			return await Task.FromResult(decorator);
		}

		[TestMethod]
		public async Task DecorateAsync_IfTheReplacementsAreChangedThroughConfiguration_ShouldWorkProperly()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = ClaimTypes.Email, Value = "1" },
				new ClaimBuilder { Type = ClaimTypes.GivenName, Value = "2" },
				new ClaimBuilder { Type = ClaimTypes.Name, Value = "3" },
				new ClaimBuilder { Type = ClaimTypes.NameIdentifier, Value = "4" }
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("Options-1", loggerFactory);

				await decorator.DecorateAsync(null, null, claims, null);

				Assert.AreEqual(4, claims.Count);

				var claim = claims.First();
				Assert.AreEqual(JwtClaimTypes.Email, claim.Type);
				Assert.AreEqual("1", claim.Value);

				claim = claims.ElementAt(1);
				Assert.AreEqual(JwtClaimTypes.GivenName, claim.Type);
				Assert.AreEqual("2", claim.Value);

				claim = claims.ElementAt(2);
				Assert.AreEqual("new_name", claim.Type);
				Assert.AreEqual("3", claim.Value);

				claim = claims.ElementAt(3);
				Assert.AreEqual(JwtClaimTypes.Subject, claim.Type);
				Assert.AreEqual("4", claim.Value);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_ShouldWorkProperly()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = ClaimTypes.Email, Value = "1" },
				new ClaimBuilder { Type = ClaimTypes.GivenName, Value = "2" },
				new ClaimBuilder { Type = ClaimTypes.Name, Value = "3" },
				new ClaimBuilder { Type = ClaimTypes.NameIdentifier, Value = "4" }
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = new MicrosoftToJwtReplacementDecorator(loggerFactory);

				await decorator.DecorateAsync(null, null, claims, null);

				Assert.AreEqual(4, claims.Count);

				var claim = claims.First();
				Assert.AreEqual(JwtClaimTypes.Email, claim.Type);
				Assert.AreEqual("1", claim.Value);

				claim = claims.ElementAt(1);
				Assert.AreEqual(JwtClaimTypes.GivenName, claim.Type);
				Assert.AreEqual("2", claim.Value);

				claim = claims.ElementAt(2);
				Assert.AreEqual(JwtClaimTypes.Name, claim.Type);
				Assert.AreEqual("3", claim.Value);

				claim = claims.ElementAt(3);
				Assert.AreEqual(JwtClaimTypes.Subject, claim.Type);
				Assert.AreEqual("4", claim.Value);
			}
		}

		[TestMethod]
		public async Task Replacements_MayBeChangedThroughConfiguration()
		{
			await Task.CompletedTask;

			var defaultNumberOfReplacements = new MicrosoftToJwtReplacementDecorator(Mock.Of<ILoggerFactory>()).Replacements.Count;

			var replacementsAfterConfiguration = (await this.CreateDecoratorAsync("Options-1", Mock.Of<ILoggerFactory>())).Replacements;
			var numberOfReplacementsAfterConfiguration = replacementsAfterConfiguration.Count;

			Assert.AreEqual(1, numberOfReplacementsAfterConfiguration - defaultNumberOfReplacements);

			Assert.AreEqual("new_name", replacementsAfterConfiguration["http%3a//schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]);
			Assert.AreEqual("claim_1", replacementsAfterConfiguration["claim_1_to_replace"]);
		}

		[TestMethod]
		public async Task Replacements_ShouldReturnACorrectedDictionary()
		{
			await Task.CompletedTask;

			var decorator = new MicrosoftToJwtReplacementDecorator(Mock.Of<ILoggerFactory>());

			Assert.AreEqual(JwtRegisteredClaimNames.NameId, JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[ClaimTypes.NameIdentifier]);
			Assert.AreEqual(JwtClaimTypes.Name, decorator.Replacements[ClaimTypes.Name.UrlEncodeColon()]);
			Assert.AreEqual(JwtClaimTypes.Subject, decorator.Replacements[ClaimTypes.NameIdentifier.UrlEncodeColon()]);
		}

		#endregion
	}
}