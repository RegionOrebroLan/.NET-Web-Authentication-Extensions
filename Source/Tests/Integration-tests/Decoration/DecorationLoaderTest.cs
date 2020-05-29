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
	public class DecorationLoaderTest
	{
		#region Methods

		[TestMethod]
		public void Test()
		{
			var services = Global.CreateServices();

			services.ScanDependencies();

			services.AddAuthentication(Global.CreateCertificateResolver(), Global.Configuration, new InstanceFactory());

			var serviceProvider = services.BuildServiceProvider();

			var decorationLoader = serviceProvider.GetRequiredService<IDecorationLoader>();

			var decorators = decorationLoader.GetAuthenticationDecoratorsAsync("Windows").Result;

			Assert.AreEqual(1, decorators.Count());
		}

		#endregion
	}
}