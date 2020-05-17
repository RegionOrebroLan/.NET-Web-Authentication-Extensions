using System.Collections.Generic;
using RegionOrebroLan.Web.Authentication;

namespace Application.Models
{
	public class HomeViewModel
	{
		#region Properties

		public virtual IList<IAuthenticationScheme> AuthenticationSchemes { get; } = new List<IAuthenticationScheme>();

		#endregion
	}
}