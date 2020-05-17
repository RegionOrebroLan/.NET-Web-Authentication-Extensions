using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.Extensions.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registrators
{
	public class FacebookRegistrator : RemoteRegistrator<FacebookOptions>
	{
		#region Methods

		protected internal override Func<string, string, Action<FacebookOptions>, AuthenticationBuilder> GetAddFunction(AuthenticationBuilder authenticationBuilder)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			return authenticationBuilder.AddFacebook;
		}

		#endregion
	}
}