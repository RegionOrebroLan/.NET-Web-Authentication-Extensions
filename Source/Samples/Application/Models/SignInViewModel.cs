using System.Collections.Generic;
using RegionOrebroLan.Web.Authentication;

namespace Application.Models
{
	public class SignInViewModel
	{
		#region Properties

		public virtual IList<IAuthenticationScheme> AuthenticationSchemes { get; } = new List<IAuthenticationScheme>();
		public virtual string ReturnUrl { get; set; }

		#endregion
	}
}