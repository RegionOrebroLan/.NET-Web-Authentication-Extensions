using System.Collections.Generic;
using System.Threading.Tasks;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	public interface IAuthenticationDecoratorLoader
	{
		#region Methods

		Task<IEnumerable<IAuthenticationDecorator>> GetDecoratorsAsync(string authenticationScheme);
		Task<IEnumerable<IAuthenticationDecorator>> GetPostDecoratorsAsync(string authenticationScheme);

		#endregion
	}
}