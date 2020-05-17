using System.Collections.Generic;
using System.Threading.Tasks;

namespace RegionOrebroLan.Web.Authentication
{
	public interface IAuthenticationSchemeLoader
	{
		#region Methods

		Task<IAuthenticationScheme> GetAsync(string name);
		Task<IAuthenticationScheme> GetDefaultAsync();
		Task<IAuthenticationScheme> GetDefaultChallengeAsync();
		Task<IAuthenticationScheme> GetDefaultForbidAsync();
		Task<IAuthenticationScheme> GetDefaultSignInAsync();
		Task<IAuthenticationScheme> GetDefaultSignOutAsync();
		Task<IEnumerable<IAuthenticationScheme>> ListAsync();
		Task<IEnumerable<IAuthenticationScheme>> ListRequestHandlerAsync();

		#endregion
	}
}