using System;
using Microsoft.Extensions.DependencyInjection;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions;

namespace IntegrationTests.Decoration
{
	public abstract class AuthenticationDecoratorTestBase
	{
		#region Methods

		protected internal virtual IServiceProvider ConfigureServices(string configurationLabel)
		{
			var configuration = Global.CreateConfiguration($"Decoration\\Resources\\AppSettings.{configurationLabel}.json");
			var services = Global.CreateServices(configuration);

			services.AddAuthentication(Global.CreateCertificateResolver(), configuration, new InstanceFactory());

			return services.BuildServiceProvider();
		}

		#endregion
	}
}