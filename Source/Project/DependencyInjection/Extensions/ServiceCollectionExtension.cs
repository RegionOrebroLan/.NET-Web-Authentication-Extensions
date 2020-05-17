using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions
{
	public static class ServiceCollectionExtension
	{
		#region Methods

		public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, IConfiguration configuration)
		{
			return services.AddAuthentication(configuration, ConfigurationKeys.AuthenticationPath);
		}

		public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, IConfiguration configuration, string configurationKey)
		{
			return services.AddAuthentication(configuration, configurationKey, _ => { });
		}

		public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, IConfiguration configuration, Action<AuthenticationOptions> postConfigureOptions)
		{
			return services.AddAuthentication(configuration, ConfigurationKeys.AuthenticationPath, postConfigureOptions);
		}

		public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, IConfiguration configuration, string configurationKey, Action<AuthenticationOptions> postConfigureOptions)
		{
			if(services == null)
				throw new ArgumentNullException(nameof(services));

			if(configuration == null)
				throw new ArgumentNullException(nameof(configuration));

			if(configurationKey == null)
				throw new ArgumentNullException(nameof(configurationKey));

			if(postConfigureOptions == null)
				throw new ArgumentNullException(nameof(postConfigureOptions));

			var authenticationBuilder = services.AddAuthentication(options => { configuration.GetSection(configurationKey)?.Bind(options); })
				.Configure(configuration, configurationKey);

			services.PostConfigure(postConfigureOptions);

			return authenticationBuilder;
		}

		#endregion
	}
}