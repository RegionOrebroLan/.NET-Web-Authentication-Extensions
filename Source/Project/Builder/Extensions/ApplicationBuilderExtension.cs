using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Server.IIS;
using Microsoft.Extensions.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Builder.Extensions
{
	public static class ApplicationBuilderExtension
	{
		#region Methods

		public static IApplicationBuilder ResolveWindowsAuthentication(this IApplicationBuilder applicationBuilder)
		{
			if(applicationBuilder == null)
				throw new ArgumentNullException(nameof(applicationBuilder));

			var windowsAuthenticationScheme = applicationBuilder.ApplicationServices.GetRequiredService<IAuthenticationSchemeLoader>().GetAsync(IISServerDefaults.AuthenticationScheme).Result;

			if(windowsAuthenticationScheme == null || !windowsAuthenticationScheme.Enabled)
				applicationBuilder.ApplicationServices.GetRequiredService<IAuthenticationSchemeProvider>().RemoveScheme(IISServerDefaults.AuthenticationScheme);

			return applicationBuilder;
		}

		#endregion
	}
}