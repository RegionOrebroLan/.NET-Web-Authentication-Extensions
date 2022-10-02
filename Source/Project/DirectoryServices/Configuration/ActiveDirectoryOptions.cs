using System.DirectoryServices.Protocols;

namespace RegionOrebroLan.Web.Authentication.DirectoryServices.Configuration
{
	public class ActiveDirectoryOptions
	{
		#region Properties

		public virtual AttributeNameOptions AttributeNames { get; set; } = new();

		/// <summary>
		/// A connection is needed if we are not on a Windows host.
		/// </summary>
		public virtual string ConnectionStringName { get; set; } = "ActiveDirectory";

		/// <summary>
		/// Can be used as default if we are on a Windows host.
		/// </summary>
		public virtual AuthType DefaultAuthenticationType { get; set; } = AuthType.Kerberos;

		public virtual PagingOptions Paging { get; set; } = new();

		/// <summary>
		/// The distinguished name for the domain, eg. "dc=example,dc=org".
		/// </summary>
		public virtual string RootDistinguishedName { get; set; }

		/// <summary>
		/// The distinguished name for the user-container, eg. "cn=users,dc=example,dc=org". By specifying this value we can increase performance when searching for user-attributes.
		/// </summary>
		public virtual string UserContainerDistinguishedName { get; set; }

		#endregion
	}
}