using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace RegionOrebroLan.Web.Authentication.DirectoryServices
{
	public interface IActiveDirectory
	{
		#region Methods

		[Obsolete("This method will be removed in a later release. Use GetUserAttributesAsync instead.")]
		Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, string identifier, IdentifierKind identifierKind);

		[Obsolete("This method will be removed in a later release. Use GetUserAttributesAsync instead.")]
		Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, IdentifierKind identifierKind, ClaimsPrincipal principal);

		/// <summary>
		/// Get user-attributes from Active Directory. The resulting key is the distinguished name for each entry. The resulting value is an attribute-dictionary. This method may return multiple hits even if that would be rare. A scenario where it could return multiple hits is when you can be employed at multiple places in the organization and when you sign in you get all your employments (employee-id) in the ticket. Then the filter passed to this method contains the "or" filter for all your employee-ids.
		/// </summary>
		/// <param name="attributes">The attributes wanted from the Active Directory. If the enumerable is empty, all attributes will be returned.</param>
		/// <param name="filter">The filter for the user. It is possible to pass a filter that will give multiple hits. Eg. "userPrincipalName=first-name.last-name@example.org" or "|(custom-id=first-id)(custom-id=second-id)". The filter will internally be used as "(&(objectClass=person)(objectClass=user)({filter}))".</param>
		/// <returns></returns>
		Task<IDictionary<string, IDictionary<string, string>>> GetUserAttributesAsync(IEnumerable<string> attributes, string filter);

		#endregion
	}
}