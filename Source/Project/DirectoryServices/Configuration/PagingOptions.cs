using System.DirectoryServices.Protocols;

namespace RegionOrebroLan.Web.Authentication.DirectoryServices.Configuration
{
	public class PagingOptions
	{
		#region Properties

		public virtual bool Enabled { get; set; } = true;
		public virtual int PageSize { get; set; } = new PageResultRequestControl().PageSize;

		#endregion
	}
}