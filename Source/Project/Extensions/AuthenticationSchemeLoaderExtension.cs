using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace RegionOrebroLan.Web.Authentication.Extensions
{
	public static class AuthenticationSchemeLoaderExtension
	{
		#region Methods

		public static async Task<IDictionary<IAuthenticationScheme, AuthenticationSchemeOptions>> GetDiagnosticsAsync(this IAuthenticationSchemeLoader authenticationSchemeLoader, IServiceProvider serviceProvider)
		{
			if(authenticationSchemeLoader == null)
				throw new ArgumentNullException(nameof(authenticationSchemeLoader));

			if(serviceProvider == null)
				throw new ArgumentNullException(nameof(serviceProvider));

			var diagnostics = new Dictionary<IAuthenticationScheme, AuthenticationSchemeOptions>();

			var schemes = await authenticationSchemeLoader.ListAsync().ConfigureAwait(false);

			foreach(var scheme in schemes)
			{
				var options = await scheme.GetOptionsDiagnosticsAsync(serviceProvider).ConfigureAwait(false);

				diagnostics.Add(scheme, options);
			}

			return diagnostics;
		}

		#endregion
	}
}