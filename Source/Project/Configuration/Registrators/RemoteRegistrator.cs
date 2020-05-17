using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registrators
{
	public abstract class RemoteRegistrator<T> : Registrator where T : RemoteAuthenticationOptions
	{
		#region Methods

		public override void Add(AuthenticationBuilder authenticationBuilder, IConfiguration configuration, string name, SchemeRegistrationOptions schemeRegistrationOptions)
		{
			if(schemeRegistrationOptions == null)
				throw new ArgumentNullException(nameof(schemeRegistrationOptions));

			this.GetAddFunction(authenticationBuilder)(name, schemeRegistrationOptions.DisplayName, options => { this.Bind(configuration, options, schemeRegistrationOptions); });
		}

		protected internal abstract Func<string, string, Action<T>, AuthenticationBuilder> GetAddFunction(AuthenticationBuilder authenticationBuilder);

		#endregion
	}
}