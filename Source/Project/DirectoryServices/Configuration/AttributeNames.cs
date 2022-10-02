namespace RegionOrebroLan.Web.Authentication.DirectoryServices.Configuration
{
	public static class AttributeNames
	{
		#region Fields

		public const string Email = "mail";
		public const string SamAccountName = "sAMAccountName";
		public const string SecurityIdentifier = "objectSid";
		public const string UserPrincipalName = "userPrincipalName";

		/// <summary>
		/// You can request this attribute but you can not use it in a filter.
		/// </summary>
		public const string WindowsAccountName = "msDS-PrincipalName";

		#endregion
	}
}