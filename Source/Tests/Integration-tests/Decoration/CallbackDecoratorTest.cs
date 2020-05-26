using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration;

namespace RegionOrebroLan.Web.Authentication.IntegrationTests.Decoration
{
	[TestClass]
	public class CallbackDecoratorTest : AuthenticationDecoratorTestBase
	{
		#region Methods

		[TestMethod]
		public void OverrideOptionsWithConfiguration_Test()
		{
			var serviceProvider = this.ConfigureServices("Callback-Decorator-Change");
			var authenticationOptions = serviceProvider.GetRequiredService<IOptions<ExtendedAuthenticationOptions>>().Value;

			Assert.AreEqual(173, authenticationOptions.PostDecorators.First().Value.AuthenticationSchemes.First().Value);

			var callbackDecorator = (CallbackDecorator) serviceProvider.GetRequiredService<IAuthenticationDecoratorLoader>().GetPostDecoratorsAsync("Any").Result.First();

			Assert.IsNotNull(callbackDecorator);
			Assert.AreEqual(4, callbackDecorator.ClaimTypeExclusions.Count);
			Assert.AreEqual("a", callbackDecorator.ClaimTypeExclusions.ElementAt(0));
			Assert.AreEqual("B", callbackDecorator.ClaimTypeExclusions.ElementAt(1));
			Assert.AreEqual("c", callbackDecorator.ClaimTypeExclusions.ElementAt(2));
			Assert.AreEqual("D", callbackDecorator.ClaimTypeExclusions.ElementAt(3));
		}

		#endregion
	}
}