using System;
using System.Collections.Generic;

namespace RegionOrebroLan.Web.Authentication.Decoration.Extensions
{
	public static class AuthenticationDecoratorLoaderExtension
	{
		#region Methods

		public static IEnumerable<IAuthenticationDecorator> GetDecorators(this IAuthenticationDecoratorLoader authenticationDecoratorLoader, string authenticationScheme)
		{
			if(authenticationDecoratorLoader == null)
				throw new ArgumentNullException(nameof(authenticationDecoratorLoader));

			return authenticationDecoratorLoader.GetDecoratorsAsync(authenticationScheme).Result;
		}

		public static IEnumerable<IAuthenticationDecorator> GetPostDecorators(this IAuthenticationDecoratorLoader authenticationDecoratorLoader, string authenticationScheme)
		{
			if(authenticationDecoratorLoader == null)
				throw new ArgumentNullException(nameof(authenticationDecoratorLoader));

			return authenticationDecoratorLoader.GetPostDecoratorsAsync(authenticationScheme).Result;
		}

		#endregion
	}
}