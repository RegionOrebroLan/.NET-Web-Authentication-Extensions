using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registrators
{
	public abstract class Registrator
	{
		#region Methods

		public abstract void Add(AuthenticationBuilder authenticationBuilder, IConfiguration configuration, string name, SchemeRegistrationOptions schemeRegistrationOptions);

		protected internal virtual void Bind(IConfiguration configuration, object instance, SchemeRegistrationOptions schemeRegistrationOptions)
		{
			if(configuration == null)
				throw new ArgumentNullException(nameof(configuration));

			if(schemeRegistrationOptions == null)
				throw new ArgumentNullException(nameof(schemeRegistrationOptions));

			foreach(var path in schemeRegistrationOptions.CommonOptionsPaths)
			{
				configuration.GetSection(path)?.Bind(instance);
			}

			schemeRegistrationOptions.Options?.Bind(instance);
		}

		#endregion
	}
}