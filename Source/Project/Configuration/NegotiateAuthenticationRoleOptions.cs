using System.Security.Claims;

namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class NegotiateAuthenticationRoleOptions
	{
		#region Properties

		/// <summary>
		/// The claim-type to use for groups / roles.
		/// </summary>
		public virtual string ClaimType { get; set; } = ClaimTypes.GroupSid;

		/// <summary>
		/// Include roles as claims. Be careful if the number of roles is large. It can result in large cookies.
		/// </summary>
		public virtual bool Include { get; set; }

		/// <summary>
		/// Translate roles.
		/// </summary>
		public virtual bool Translate { get; set; } = true;

		#endregion
	}
}