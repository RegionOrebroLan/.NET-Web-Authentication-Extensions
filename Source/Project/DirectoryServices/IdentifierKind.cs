namespace RegionOrebroLan.Web.Authentication.DirectoryServices
{
	public enum IdentifierKind
	{
		Email,
		SamAccountName,
		SecurityIdentifier,
		UserPrincipalName,

		/// <summary>
		/// To find the Active Directory entry having a UserPrincipalName with the value from the UserPrincipalName-claim-value or the Email-claim-value. There are scenarios, when logging in with smart cards, when the certificate on the smart card contains an invalid UserPrincipalName-value (coming from a distinguished name component) but the Email-value (coming from a distinguished name component) is the correct UserPrincipalName-value. In those scenarios we can use this identifier-kind.
		/// </summary>
		UserPrincipalNameWithEmailFallback,
		WindowsAccountName
	}
}