using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Configuration.Registrators;

namespace RegionOrebroLan.Web.Authentication.Extensions
{
	public static class AuthenticationBuilderExtension
	{
		#region Methods

		public static AuthenticationBuilder Configure(this AuthenticationBuilder authenticationBuilder, IConfiguration configuration)
		{
			return authenticationBuilder.Configure(configuration, ConfigurationKeys.AuthenticationPath);
		}

		public static AuthenticationBuilder Configure(this AuthenticationBuilder authenticationBuilder, IConfiguration configuration, string configurationKey)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			if(configuration == null)
				throw new ArgumentNullException(nameof(configuration));

			if(configurationKey == null)
				throw new ArgumentNullException(nameof(configurationKey));

			var configurationSection = configuration.GetSection(configurationKey);
			authenticationBuilder.Services.Configure<ExtendedAuthenticationOptions>(configurationSection);
			var extendedAuthenticationOptions = new ExtendedAuthenticationOptions();
			configurationSection.Bind(extendedAuthenticationOptions);

			foreach(var (key, value) in extendedAuthenticationOptions.SchemeRegistrations)
			{
				if(!value.Enabled)
					continue;

				var registrator = (Registrator) Activator.CreateInstance(Type.GetType(value.Type, true, true));

				// ReSharper disable PossibleNullReferenceException
				registrator.Add(authenticationBuilder, configuration, key, value);
				// ReSharper restore PossibleNullReferenceException
			}

			authenticationBuilder.Services.TryAddSingleton<IAuthenticationSchemeLoader, AuthenticationSchemeLoader>();

			return authenticationBuilder;
		}

		#endregion
	}
}