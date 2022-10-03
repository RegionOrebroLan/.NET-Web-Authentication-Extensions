using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using RegionOrebroLan.Web.Authentication.Decoration.Configuration;
using RegionOrebroLan.Web.Authentication.DirectoryServices.Configuration;

namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class ExtendedAuthenticationOptions : AuthenticationOptions
	{
		#region Properties

		public virtual ActiveDirectoryOptions ActiveDirectory { get; set; } = new();
		public virtual IDictionary<string, DecoratorOptions> AuthenticationDecorators { get; } = new Dictionary<string, DecoratorOptions>(StringComparer.OrdinalIgnoreCase);
		public virtual IDictionary<string, DecoratorOptions> AuthenticationPropertiesDecorators { get; } = new Dictionary<string, DecoratorOptions>(StringComparer.OrdinalIgnoreCase);
		public virtual IDictionary<string, DecoratorOptions> CallbackDecorators { get; } = new Dictionary<string, DecoratorOptions>(StringComparer.OrdinalIgnoreCase);
		public virtual NegotiateAuthenticationOptions Negotiate { get; set; } = new();
		public virtual IDictionary<string, SchemeRegistrationOptions> SchemeRegistrations { get; } = new Dictionary<string, SchemeRegistrationOptions>(StringComparer.OrdinalIgnoreCase);

		#endregion
	}
}