using RegionOrebroLan.Configuration;

namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class SelectableDynamicOptions : DynamicOptions
	{
		#region Properties

		public virtual bool Enabled { get; set; } = true;
		public virtual int Index { get; set; } = 1000;

		#endregion
	}
}