using System.Collections.Generic;
using Microsoft.Extensions.Configuration;

namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class SchemeRegistrationOptions
	{
		#region Properties

		public virtual IList<string> CommonOptionsPaths { get; } = new List<string>();
		public virtual string DisplayName { get; set; }
		public virtual bool Enabled { get; set; } = true;
		public virtual string Icon { get; set; }
		public virtual int Index { get; set; } = 1000;

		/// <summary>
		/// If set to false the scheme will not be available at interactive sign-in.
		/// </summary>
		public virtual bool Interactive { get; set; } = true;

		public virtual IConfigurationSection Options { get; set; }
		public virtual bool SignOutSupport { get; set; }
		public virtual string Type { get; set; }

		#endregion
	}
}