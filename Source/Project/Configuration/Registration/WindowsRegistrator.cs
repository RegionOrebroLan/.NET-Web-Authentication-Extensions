using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registration
{
	public class WindowsRegistrator : Registrator
	{
		#region Methods

		public override void Add(ExtendedAuthenticationBuilder authenticationBuilder, string name, SchemeRegistrationOptions schemeRegistrationOptions)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			authenticationBuilder.Services.Configure<IISOptions>(options =>
			{
				options.AuthenticationDisplayName = schemeRegistrationOptions.DisplayName;
				options.AutomaticAuthentication = false;

				this.Bind(authenticationBuilder, options, schemeRegistrationOptions);
			});

			authenticationBuilder.Services.Configure<IISServerOptions>(options =>
			{
				options.AuthenticationDisplayName = schemeRegistrationOptions.DisplayName;
				options.AutomaticAuthentication = false;

				this.Bind(authenticationBuilder, options, schemeRegistrationOptions);
			});
		}

		#endregion
	}
}