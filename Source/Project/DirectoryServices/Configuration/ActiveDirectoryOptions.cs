using System.DirectoryServices.Protocols;

namespace RegionOrebroLan.Web.Authentication.DirectoryServices.Configuration
{
	public class ActiveDirectoryOptions
	{
		#region Properties

		public virtual AuthType AuthenticationType { get; set; } = AuthType.Kerberos;
		public virtual bool Impersonate { get; set; }
		public virtual int? Port { get; set; }

		#endregion
	}
}