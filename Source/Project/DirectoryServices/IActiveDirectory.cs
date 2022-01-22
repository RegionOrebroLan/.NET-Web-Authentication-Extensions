using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace RegionOrebroLan.Web.Authentication.DirectoryServices
{
	public interface IActiveDirectory
	{
		#region Methods

		Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, string identifier, IdentifierKind identifierKind);
		Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, IdentifierKind identifierKind, ClaimsPrincipal principal);

		#endregion
	}
}