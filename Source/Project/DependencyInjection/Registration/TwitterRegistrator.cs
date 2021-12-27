using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Twitter;
using Microsoft.Extensions.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.DependencyInjection.Registration
{
	public class TwitterRegistrator : RemoteRegistrator<TwitterOptions>
	{
		#region Methods

		protected internal override Func<string, string, Action<TwitterOptions>, AuthenticationBuilder> GetAddFunction(AuthenticationBuilder authenticationBuilder)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			return authenticationBuilder.AddTwitter;
		}

		#endregion
	}
}