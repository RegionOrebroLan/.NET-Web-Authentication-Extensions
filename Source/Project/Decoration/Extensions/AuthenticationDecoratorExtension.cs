using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
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

		public static void Initialize(this IAuthenticationDecorator authenticationDecorator, IConfigurationSection optionsConfiguration)
		{
			if(authenticationDecorator == null)
				throw new ArgumentNullException(nameof(authenticationDecorator));

			authenticationDecorator.InitializeAsync(optionsConfiguration).Wait();
		}

		#endregion
	}
}