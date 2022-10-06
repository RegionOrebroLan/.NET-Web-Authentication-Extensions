using System.Security.Claims;

namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class NegotiateAuthenticationOptions
	{
		#region Properties

		public virtual bool IncludeNameClaimAsWindowsAccountNameClaim { get; set; }
		public virtual bool IncludeSecurityIdentifierClaim { get; set; } = true;

		/// <summary>
		/// Options for handling roles.
		/// </summary>
		public virtual NegotiateAuthenticationRoleOptions Roles { get; set; } = new();

		/// <summary>
		/// The claim-type to use for the unique identifier claim (sub/nameidentifier). Negotiate authentication do not add a unique identifier claim.
		/// </summary>
		public virtual string UniqueIdentifierClaimType { get; set; } = ClaimTypes.PrimarySid;

		#endregion
	}
}