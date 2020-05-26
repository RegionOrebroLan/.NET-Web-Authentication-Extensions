using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Security.Cryptography;
using RegionOrebroLan.Web.Authentication.Configuration;

namespace RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions
{
	public static class ServiceCollectionExtension
	{
		#region Methods

		public static ExtendedAuthenticationBuilder AddAuthentication(this IServiceCollection services, ICertificateResolver certificateResolver, IConfiguration configuration, IInstanceFactory instanceFactory)
		{
			return services.AddAuthentication(certificateResolver, configuration, ConfigurationKeys.AuthenticationPath, instanceFactory);
		}

		public static ExtendedAuthenticationBuilder AddAuthentication(this IServiceCollection services, ICertificateResolver certificateResolver, IConfiguration configuration, string configurationKey, IInstanceFactory instanceFactory)
		{
			return services.AddAuthentication(certificateResolver, configuration, configurationKey, instanceFactory, _ => { });
		}

		public static ExtendedAuthenticationBuilder AddAuthentication(this IServiceCollection services, ICertificateResolver certificateResolver, IConfiguration configuration, IInstanceFactory instanceFactory, Action<AuthenticationOptions> postConfigureOptions)
		{
			return services.AddAuthentication(certificateResolver, configuration, ConfigurationKeys.AuthenticationPath, instanceFactory, postConfigureOptions);
		}

		public static ExtendedAuthenticationBuilder AddAuthentication(this IServiceCollection services, ICertificateResolver certificateResolver, IConfiguration configuration, string configurationKey, IInstanceFactory instanceFactory, Action<AuthenticationOptions> postConfigureOptions)
		{
			if(services == null)
				throw new ArgumentNullException(nameof(services));

			if(certificateResolver == null)
				throw new ArgumentNullException(nameof(certificateResolver));

			if(configuration == null)
				throw new ArgumentNullException(nameof(configuration));

			if(configurationKey == null)
				throw new ArgumentNullException(nameof(configurationKey));

			if(instanceFactory == null)
				throw new ArgumentNullException(nameof(instanceFactory));

			if(postConfigureOptions == null)
				throw new ArgumentNullException(nameof(postConfigureOptions));

			services.AddAuthentication(options => { configuration.GetSection(configurationKey)?.Bind(options); });

			var authenticationBuilder = new ExtendedAuthenticationBuilder(services)
			{
				CertificateResolver = certificateResolver,
				Configuration = configuration,
				ConfigurationKey = configurationKey,
				InstanceFactory = instanceFactory,
			}.Configure();

			services.PostConfigure(postConfigureOptions);

			return authenticationBuilder;
		}

		#endregion
	}
}