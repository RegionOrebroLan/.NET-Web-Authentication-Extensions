using System.Collections.Generic;
using RegionOrebroLan.Web.Authentication;

namespace Application.Models
{
	public class HomeViewModel
	{
		#region Properties

		public virtual IDictionary<IAuthenticationScheme, string> AuthenticationSchemes { get; } = new Dictionary<IAuthenticationScheme, string>();

		#endregion
	}
}