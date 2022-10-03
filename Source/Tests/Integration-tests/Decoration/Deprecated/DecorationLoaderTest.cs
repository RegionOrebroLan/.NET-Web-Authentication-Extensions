using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.DependencyInjection.Extensions;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions;

namespace IntegrationTests.Decoration.Deprecated
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

			var decorators = decorationLoader.GetAuthenticationDecoratorsAsync("*").Result;

			Assert.IsFalse(decorators.Any());
		}

		#endregion
	}
}