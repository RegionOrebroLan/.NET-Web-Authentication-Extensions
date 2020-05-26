using System;
using Microsoft.Extensions.Configuration;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registration
{
	public abstract class Registrator
	{
		#region Methods

		public abstract void Add(ExtendedAuthenticationBuilder authenticationBuilder, string name, SchemeRegistrationOptions schemeRegistrationOptions);

		protected internal virtual void Bind(ExtendedAuthenticationBuilder authenticationBuilder, object instance, SchemeRegistrationOptions schemeRegistrationOptions)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			if(schemeRegistrationOptions == null)
				throw new ArgumentNullException(nameof(schemeRegistrationOptions));

			foreach(var path in schemeRegistrationOptions.CommonOptionsPaths)
			{
				authenticationBuilder.Configuration.GetSection(path)?.Bind(instance);
			}

			schemeRegistrationOptions.Options?.Bind(instance);
		}

		#endregion
	}
}