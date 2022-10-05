namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class NegotiateAuthenticationOptions
	{
		#region Properties

		/// <summary>
		/// Options for handling roles.
		/// </summary>
		public virtual NegotiateAuthenticationRoleOptions Roles { get; set; } = new();

		#endregion
	}
}