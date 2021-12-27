using System;
using Microsoft.Extensions.DependencyInjection;
using RegionOrebroLan.Web.Authentication.Configuration;

namespace RegionOrebroLan.Web.Authentication.DependencyInjection.Registration
{
	public class CookieRegistrator : Registrator
	{
		#region Methods

		public override void Add(ExtendedAuthenticationBuilder authenticationBuilder, string name, SchemeRegistrationOptions schemeRegistrationOptions)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			if(schemeRegistrationOptions == null)
				throw new ArgumentNullException(nameof(schemeRegistrationOptions));

			authenticationBuilder.AddCookie(name, schemeRegistrationOptions.DisplayName, options => { this.Bind(authenticationBuilder, options, schemeRegistrationOptions); });
		}

		#endregion
	}
}