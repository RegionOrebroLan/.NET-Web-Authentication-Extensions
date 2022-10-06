namespace RegionOrebroLan.Web.Authentication.DirectoryServices.Configuration
{
	public class AttributeNameOptions
	{
		#region Properties

		public virtual string Email { get; set; } = AttributeNames.Email;
		public virtual string SamAccountName { get; set; } = AttributeNames.SamAccountName;
		public virtual string SecurityIdentifier { get; set; } = AttributeNames.SecurityIdentifier;
		public virtual string UserPrincipalName { get; set; } = AttributeNames.UserPrincipalName;

		#endregion
	}
}