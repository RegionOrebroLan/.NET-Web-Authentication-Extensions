using System;
using Microsoft.AspNetCore.Authentication;
using RegionOrebroLan.Web.Authentication.Configuration;

namespace RegionOrebroLan.Web.Authentication.DependencyInjection.Registration
{
	public abstract class RemoteRegistrator<T> : Registrator where T : RemoteAuthenticationOptions
	{
		#region Methods

		public override void Add(ExtendedAuthenticationBuilder authenticationBuilder, string name, SchemeRegistrationOptions schemeRegistrationOptions)
		{
			if(schemeRegistrationOptions == null)
				throw new ArgumentNullException(nameof(schemeRegistrationOptions));

			this.GetAddFunction(authenticationBuilder)(name, schemeRegistrationOptions.DisplayName, options => { this.Bind(authenticationBuilder, options, schemeRegistrationOptions); });
		}

		protected internal abstract Func<string, string, Action<T>, AuthenticationBuilder> GetAddFunction(AuthenticationBuilder authenticationBuilder);

		#endregion
	}
}