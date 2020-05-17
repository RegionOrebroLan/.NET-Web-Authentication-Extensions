using System;
using System.Threading.Tasks;
using Application.Models;
using Microsoft.AspNetCore.Mvc;
using RegionOrebroLan.Web.Authentication;

namespace Application.Controllers
{
	public class HomeController : Controller
	{
		#region Constructors

		public HomeController(IAuthenticationSchemeLoader authenticationSchemeLoader)
		{
			this.AuthenticationSchemeLoader = authenticationSchemeLoader ?? throw new ArgumentNullException(nameof(authenticationSchemeLoader));
		}

		#endregion

		#region Properties

		protected internal virtual IAuthenticationSchemeLoader AuthenticationSchemeLoader { get; }

		#endregion

		#region Methods

		public virtual async Task<IActionResult> Index()
		{
			return await Task.FromResult(this.View());
		}

		public virtual async Task<IActionResult> Schemes()
		{
			var model = new HomeViewModel();

			foreach(var authenticationScheme in await this.AuthenticationSchemeLoader.ListAsync())
			{
				model.AuthenticationSchemes.Add(authenticationScheme);
			}

			return await Task.FromResult(this.View(model));
		}

		#endregion
	}
}