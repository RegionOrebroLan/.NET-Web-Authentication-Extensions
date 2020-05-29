using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication;

namespace RegionOrebroLan.Web.Authentication.Decoration.Extensions
{
	public static class AuthenticationPropertiesDecoratorExtension
	{
		#region Methods

		[SuppressMessage("Design", "CA1054:Uri parameters should not be strings")]
		public static void Decorate(this IAuthenticationPropertiesDecorator authenticationPropertiesDecorator, string authenticationScheme, AuthenticationProperties properties, string returnUrl)
		{
			if(authenticationPropertiesDecorator == null)
				throw new ArgumentNullException(nameof(authenticationPropertiesDecorator));

			authenticationPropertiesDecorator.DecorateAsync(authenticationScheme, properties, returnUrl).Wait();
		}

		#endregion
	}
}