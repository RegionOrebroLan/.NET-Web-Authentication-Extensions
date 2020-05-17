using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registrators
{
	public class OpenIdConnectRegistrator : RemoteRegistrator<OpenIdConnectOptions>
	{
		#region Methods

		protected internal override Func<string, string, Action<OpenIdConnectOptions>, AuthenticationBuilder> GetAddFunction(AuthenticationBuilder authenticationBuilder)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			return authenticationBuilder.AddOpenIdConnect;
		}

		#endregion
	}
}