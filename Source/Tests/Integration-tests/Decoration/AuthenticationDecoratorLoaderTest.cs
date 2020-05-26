using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.DependencyInjection.Extensions;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions;

namespace RegionOrebroLan.Web.Authentication.IntegrationTests.Decoration
{
	[TestClass]
	public class AuthenticationDecoratorLoaderTest
	{
		#region Methods

		[TestMethod]
		public void Test()
		{
			var services = Global.CreateServices();

			services.ScanDependencies();

			services.AddAuthentication(Global.CreateCertificateResolver(), Global.Configuration, new InstanceFactory());

			var serviceProvider = services.BuildServiceProvider();

			var authenticationDecoratorLoader = serviceProvider.GetRequiredService<IAuthenticationDecoratorLoader>();

			var decorators = authenticationDecoratorLoader.GetDecoratorsAsync("Windows").Result;

			Assert.AreEqual(1, decorators.Count());
		}

		#endregion
	}
}