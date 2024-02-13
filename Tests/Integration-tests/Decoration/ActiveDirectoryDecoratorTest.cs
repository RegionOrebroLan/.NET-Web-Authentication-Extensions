using System.Security.Principal;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Decoration;

namespace IntegrationTests.Decoration
{
	[TestClass]
	public class ActiveDirectoryDecoratorTest : DecoratorTestBase
	{
		#region Methods

		[TestMethod]
		public async Task NegotiateAuthentication_SecurityIdentifier_Test()
		{
			var windowsIdentity = WindowsIdentity.GetCurrent();

			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = JwtClaimTypes.Email, Value = "Email" },
				new ClaimBuilder { Type = JwtClaimTypes.GivenName, Value = "Given name" },
				new ClaimBuilder { Type = JwtClaimTypes.Name, Value = "Name" },
				new ClaimBuilder { Type = "primarysid", Value = windowsIdentity.User?.Value },
				new ClaimBuilder { Type = JwtClaimTypes.Subject, Value = "Subject" },
				new ClaimBuilder { Type = "upn", Value = "User-principal-name" }
			};

			var configuration = await this.CreateConfigurationAsync("NegotiateAuthentication-SecurityIdentifier");

			await using(var serviceProvider = await this.CreateServiceProviderAsync())
			{
				var decorator = serviceProvider.GetRequiredService<ActiveDirectoryDecorator>();
				await decorator.InitializeAsync(configuration);
				await decorator.DecorateAsync(null, null, claims, null);

				Assert.AreEqual(6, claims.Count);
				Assert.AreEqual("Given name", claims[0].Value, "The test must be run on a domain.");
				Assert.AreEqual("Name", claims[1].Value, "The test must be run on a domain.");
				Assert.AreEqual(windowsIdentity.User?.Value, claims[2].Value, "The test must be run on a domain.");
				Assert.AreEqual("Subject", claims[3].Value, "The test must be run on a domain.");
				Assert.AreEqual(JwtClaimTypes.Email, claims[4].Type, "The test must be run on a domain.");
				Assert.AreEqual("upn", claims[5].Type, "The test must be run on a domain.");
			}
		}

		#endregion
	}
}