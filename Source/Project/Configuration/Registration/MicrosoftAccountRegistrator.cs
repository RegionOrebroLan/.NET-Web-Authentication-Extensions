using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.Extensions.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registration
{
	public class MicrosoftAccountRegistrator : RemoteRegistrator<MicrosoftAccountOptions>
	{
		#region Methods

		protected internal override Func<string, string, Action<MicrosoftAccountOptions>, AuthenticationBuilder> GetAddFunction(AuthenticationBuilder authenticationBuilder)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			return authenticationBuilder.AddMicrosoftAccount;
		}

		#endregion
	}
}