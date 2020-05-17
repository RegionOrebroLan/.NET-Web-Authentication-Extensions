using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.WsFederation;
using Microsoft.Extensions.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registrators
{
	public class WsFederationRegistrator : RemoteRegistrator<WsFederationOptions>
	{
		#region Methods

		protected internal override Func<string, string, Action<WsFederationOptions>, AuthenticationBuilder> GetAddFunction(AuthenticationBuilder authenticationBuilder)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			return authenticationBuilder.AddWsFederation;
		}

		#endregion
	}
}