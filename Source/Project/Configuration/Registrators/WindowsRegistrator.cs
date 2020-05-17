using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registrators
{
	public class WindowsRegistrator : Registrator
	{
		#region Methods

		public override void Add(AuthenticationBuilder authenticationBuilder, IConfiguration configuration, string name, SchemeRegistrationOptions schemeRegistrationOptions)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			authenticationBuilder.Services.Configure<IISOptions>(options =>
			{
				options.AuthenticationDisplayName = schemeRegistrationOptions.DisplayName;
				options.AutomaticAuthentication = false;

				this.Bind(configuration, options, schemeRegistrationOptions);
			});

			authenticationBuilder.Services.Configure<IISServerOptions>(options =>
			{
				options.AuthenticationDisplayName = schemeRegistrationOptions.DisplayName;
				options.AutomaticAuthentication = false;

				this.Bind(configuration, options, schemeRegistrationOptions);
			});
		}

		#endregion
	}
}