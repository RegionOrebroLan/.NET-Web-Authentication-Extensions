using System.Collections.Generic;
using System.Threading.Tasks;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	public interface IDecorationLoader
	{
		#region Methods

		Task<IEnumerable<IAuthenticationDecorator>> GetAuthenticationDecoratorsAsync(string authenticationScheme);
		Task<IEnumerable<IAuthenticationPropertiesDecorator>> GetAuthenticationPropertiesDecoratorsAsync(string authenticationScheme);
		Task<IEnumerable<IAuthenticationDecorator>> GetCallbackDecoratorsAsync(string authenticationScheme);

		#endregion
	}
}