using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Server.IIS;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.Decoration.Configuration;
using RegionOrebroLan.Web.Authentication.DirectoryServices.Configuration;

namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class ExtendedAuthenticationOptions : AuthenticationOptions
	{
		#region Properties

		public virtual ActiveDirectoryOptions ActiveDirectory { get; set; } = new ActiveDirectoryOptions();

		public virtual IDictionary<string, DecoratorOptions> AuthenticationDecorators { get; } = new Dictionary<string, DecoratorOptions>(StringComparer.OrdinalIgnoreCase)
		{
			{
				$"{IISServerDefaults.AuthenticationScheme}-Decorator", new DecoratorOptions
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

		public virtual IDictionary<string, DecoratorOptions> AuthenticationPropertiesDecorators { get; } = new Dictionary<string, DecoratorOptions>(StringComparer.OrdinalIgnoreCase);

		public virtual IDictionary<string, DecoratorOptions> CallbackDecorators { get; } = new Dictionary<string, DecoratorOptions>(StringComparer.OrdinalIgnoreCase)
		{
			{
				"Callback-Decorator", new DecoratorOptions
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