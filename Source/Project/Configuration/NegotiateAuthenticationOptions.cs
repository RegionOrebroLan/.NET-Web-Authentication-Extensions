namespace RegionOrebroLan.Web.Authentication.Configuration
{
	public class NegotiateAuthenticationOptions
	{
		#region Properties

		/// <summary>
		/// Include roles as claims. Be careful if the number of roles is large. It can result in large cookies.
		/// </summary>
		public virtual bool IncludeRoleClaims { get; set; }

		#endregion
	}
}