using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.Security.Cryptography;
using RegionOrebroLan.Web.Authentication.Test.Mocks.Logging;

namespace RegionOrebroLan.Web.Authentication.IntegrationTests
{
	// ReSharper disable All
	[SuppressMessage("Naming", "CA1716:Identifiers should not match keywords")]
	public static class Global
	{
		#region Fields

		private static IConfiguration _configuration;
		private static IHostEnvironment _hostEnvironment;
		public static readonly string ProjectDirectoryPath = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory).Parent.Parent.Parent.FullName;

		#endregion

		#region Properties

		public static IConfiguration Configuration
		{
			get
			{
				if(_configuration == null)
				{
					var configurationBuilder = CreateConfigurationBuilder();

					_configuration = configurationBuilder
						.AddJsonFile("AppSettings.json", true, true)
						.Build();
				}

				return _configuration;
			}
		}

		public static IHostEnvironment HostEnvironment => _hostEnvironment ??= CreateHostEnvironment("Integration-tests");

		#endregion

		#region Methods

		public static ICertificateResolver CreateCertificateResolver()
		{
			var services = new ServiceCollection();

			services.AddSingleton(AppDomain.CurrentDomain);
			services.AddSingleton<FileCertificateResolver>();
			services.AddSingleton(HostEnvironment);
			services.AddSingleton<IApplicationDomain, ApplicationHost>();
			services.AddSingleton<ICertificateResolver, CertificateResolver>();
			services.AddSingleton<StoreCertificateResolver>();

			return services.BuildServiceProvider().GetRequiredService<ICertificateResolver>();
		}

		public static IConfigurationBuilder CreateConfigurationBuilder()
		{
			var configurationBuilder = new ConfigurationBuilder();
			configurationBuilder.Properties.Add("FileProvider", HostEnvironment.ContentRootFileProvider);
			return configurationBuilder;
		}

		public static IHostEnvironment CreateHostEnvironment(string environmentName)
		{
			return new HostingEnvironment
			{
				ApplicationName = typeof(Global).Assembly.GetName().Name,
				ContentRootFileProvider = new PhysicalFileProvider(ProjectDirectoryPath),
				ContentRootPath = ProjectDirectoryPath,
				EnvironmentName = environmentName
			};
		}

		public static IServiceCollection CreateServices()
		{
			var services = new ServiceCollection();

			services.AddSingleton(Configuration);
			services.AddSingleton(HostEnvironment);
			services.AddSingleton<ILoggerFactory, LoggerFactoryMock>();

			return services;
		}

		#endregion
	}
	// ReSharper restore All
}