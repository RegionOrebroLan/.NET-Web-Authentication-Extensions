using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;

namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class ExtendedAuthenticationOptions : AuthenticationOptions
	{
		#region Properties

		public virtual IDictionary<string, SchemeRegistrationOptions> SchemeRegistrations { get; } = new Dictionary<string, SchemeRegistrationOptions>(StringComparer.OrdinalIgnoreCase);
		public virtual WindowsAuthenticationOptions Windows { get; set; } = new WindowsAuthenticationOptions();

		#endregion
	}
}