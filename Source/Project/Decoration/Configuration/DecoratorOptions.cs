using System;
using System.Collections.Generic;
using RegionOrebroLan.Configuration;

namespace RegionOrebroLan.Web.Authentication.Decoration.Configuration
{
	public class DecoratorOptions : DynamicOptions
	{
		#region Properties

		/// <summary>
		/// Map to authentication-schemes. A dictionary where the key is a name for an authentication-scheme or a name-pattern for authentication-schemes. The key support wildcards. The value is the index used to decide the order of the entry.
		/// </summary>
		public virtual IDictionary<string, int> AuthenticationSchemes { get; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

		public virtual bool Enabled { get; set; } = true;

		#endregion
	}
}