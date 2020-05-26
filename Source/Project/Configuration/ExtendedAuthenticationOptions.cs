using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Server.IIS;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.Decoration.Configuration;

namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class ExtendedAuthenticationOptions : AuthenticationOptions
	{
		#region Properties

		public virtual IDictionary<string, AuthenticationDecoratorOptions> Decorators { get; } = new Dictionary<string, AuthenticationDecoratorOptions>(StringComparer.OrdinalIgnoreCase)
		{
			{
				$"{IISServerDefaults.AuthenticationScheme}-Decorator", new AuthenticationDecoratorOptions
				{
					AuthenticationSchemes =
					{
						{
							IISServerDefaults.AuthenticationScheme, 10
						}
					},
					Type = typeof(WindowsAuthenticationDecorator).AssemblyQualifiedName
				}
			}
		};

		public virtual IDictionary<string, AuthenticationDecoratorOptions> PostDecorators { get; } = new Dictionary<string, AuthenticationDecoratorOptions>(StringComparer.OrdinalIgnoreCase)
		{
			{
				"Callback-Decorator", new AuthenticationDecoratorOptions
				{
					AuthenticationSchemes =
					{
						{
							"*", 10
						}
					},
					Type = typeof(CallbackDecorator).AssemblyQualifiedName
				}
			}
		};

		public virtual IDictionary<string, SchemeRegistrationOptions> SchemeRegistrations { get; } = new Dictionary<string, SchemeRegistrationOptions>(StringComparer.OrdinalIgnoreCase);
		public virtual WindowsAuthenticationOptions Windows { get; set; } = new WindowsAuthenticationOptions();

		#endregion
	}
}