using System;
using Microsoft.AspNetCore.Authentication;
using RegionOrebroLan.Security.Claims;

namespace RegionOrebroLan.Web.Authentication.Decoration.Extensions
{
	public static class AuthenticationDecoratorExtension
	{
		#region Methods

		public static void Decorate(this IAuthenticationDecorator authenticationDecorator, AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			if(authenticationDecorator == null)
				throw new ArgumentNullException(nameof(authenticationDecorator));

			authenticationDecorator.DecorateAsync(authenticateResult, authenticationScheme, claims, properties).Wait();
		}

		#endregion
	}
}