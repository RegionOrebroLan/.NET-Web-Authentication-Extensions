using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.DependencyInjection.Extensions;
using RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions;

namespace IntegrationTests.Decoration
{
	public abstract class DecoratorTestBase
	{
		#region Fields

		private string _resourceDirectoryPath;

		#endregion

		#region Properties

		protected internal virtual string ResourceDirectoryPath => this._resourceDirectoryPath ??= Path.Combine(new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory).Parent.Parent.Parent.FullName, @"Decoration\Resources", this.GetType().Name);

		#endregion

		#region Methods

		protected internal virtual async Task<IConfiguration> CreateConfigurationAsync(string fileName)
		{
			var filePath = Path.Combine(this.ResourceDirectoryPath, $"{fileName}.json");

			var configurationBuilder = new ConfigurationBuilder();

			configurationBuilder.AddJsonFile(filePath);

			var configuration = configurationBuilder.Build();

			return await Task.FromResult(configuration);
		}

		protected internal virtual async Task<ServiceProvider> CreateServiceProviderAsync(IConfiguration configuration = null)
		{
			var services = configuration == null ? Global.CreateServices() : Global.CreateServices(configuration);

			services.ScanDependencies();

			services.AddAuthentication(Global.CreateCertificateResolver(), Global.Configuration, new InstanceFactory());

			return await Task.FromResult(services.BuildServiceProvider());
		}

		#endregion
	}
}