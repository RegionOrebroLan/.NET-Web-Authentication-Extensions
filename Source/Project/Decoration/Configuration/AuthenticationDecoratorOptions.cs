using System;
using System.Collections.Generic;
using RegionOrebroLan.Configuration;

namespace RegionOrebroLan.Web.Authentication.Decoration.Configuration
{
	public class AuthenticationDecoratorOptions : DynamicOptions
	{
		#region Properties

		public virtual IDictionary<string, int> AuthenticationSchemes { get; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		public virtual bool Enabled { get; set; } = true;

		#endregion
	}
}