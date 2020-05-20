using System.Collections.Generic;

namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class SchemeRegistrationOptions : SelectableDynamicOptions
	{
		#region Properties

		public virtual IList<string> CommonOptionsPaths { get; } = new List<string>();
		public virtual string DisplayName { get; set; }
		public virtual string Icon { get; set; }

		/// <summary>
		/// If set to false the scheme will not be available at interactive sign-in.
		/// </summary>
		public virtual bool Interactive { get; set; } = true;

		public virtual bool SignOutSupport { get; set; }

		#endregion
	}
}