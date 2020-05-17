using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registrators
{
	public class CookieRegistrator : Registrator
	{
		#region Methods

		public override void Add(AuthenticationBuilder authenticationBuilder, IConfiguration configuration, string name, SchemeRegistrationOptions schemeRegistrationOptions)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			if(configuration == null)
				throw new ArgumentNullException(nameof(configuration));

			if(schemeRegistrationOptions == null)
				throw new ArgumentNullException(nameof(schemeRegistrationOptions));

			authenticationBuilder.AddCookie(name, schemeRegistrationOptions.DisplayName, options => { this.Bind(configuration, options, schemeRegistrationOptions); });
		}

		#endregion
	}
}