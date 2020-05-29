using System;
using System.Collections.Generic;

namespace RegionOrebroLan.Web.Authentication.Decoration.Extensions
{
	public static class DecorationLoaderExtension
	{
		#region Methods

		public static IEnumerable<IAuthenticationDecorator> GetAuthenticationDecorators(this IDecorationLoader decorationLoader, string authenticationScheme)
		{
			if(decorationLoader == null)
				throw new ArgumentNullException(nameof(decorationLoader));

			return decorationLoader.GetAuthenticationDecoratorsAsync(authenticationScheme).Result;
		}

		public static IEnumerable<IAuthenticationPropertiesDecorator> GetAuthenticationPropertiesDecorators(this IDecorationLoader decorationLoader, string authenticationScheme)
		{
			if(decorationLoader == null)
				throw new ArgumentNullException(nameof(decorationLoader));

			return decorationLoader.GetAuthenticationPropertiesDecoratorsAsync(authenticationScheme).Result;
		}

		public static IEnumerable<IAuthenticationDecorator> GetCallbackDecorators(this IDecorationLoader decorationLoader, string authenticationScheme)
		{
			if(decorationLoader == null)
				throw new ArgumentNullException(nameof(decorationLoader));

			return decorationLoader.GetCallbackDecoratorsAsync(authenticationScheme).Result;
		}

		#endregion
	}
}