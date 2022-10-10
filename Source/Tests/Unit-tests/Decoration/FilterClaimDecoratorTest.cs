using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
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
	public class FilterClaimDecoratorTest : DecoratorTestBase
	{
		#region Methods

		protected internal virtual async Task<FilterClaimDecorator> CreateDecoratorAsync(ILoggerFactory loggerFactory)
		{
			var filterClaimDecoratorMock = new Mock<FilterClaimDecorator>(loggerFactory) { CallBase = true };

			filterClaimDecoratorMock.Setup(filterClaimDecorator => filterClaimDecorator.FilterAsync(It.IsAny<IClaimBuilderCollection>()));

			return await Task.FromResult(filterClaimDecoratorMock.Object);
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
				var decorator = await this.CreateDecoratorAsync(loggerFactory);
				decorator.PrincipalClaimsAsSource = false;

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.AreEqual(8, claims.Count);
				Assert.AreEqual(4, claims.Count(claim => claim.Type == "claim_1"));
				Assert.AreEqual(4, claims.Count(claim => claim.Type == "claim_2"));
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
				var decorator = await this.CreateDecoratorAsync(loggerFactory);
				decorator.PrincipalClaimsAsSource = true;

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.AreEqual(8, claims.Count);
				Assert.AreEqual(4, claims.Count(claim => claim.Type == "claim_1"));
				Assert.AreEqual(4, claims.Count(claim => claim.Type == "claim_2"));
			}
		}

		#endregion
	}
}