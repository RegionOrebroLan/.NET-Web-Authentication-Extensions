using System;
using System.Linq;
using System.Threading.Tasks;
using Application.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using RegionOrebroLan.Web.Authentication;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace Application.Controllers
{
	[Authorize]
	public class AccountController : Controller
	{
		#region Constructors

		public AccountController(IOptions<ExtendedAuthenticationOptions> authenticationOptions, IAuthenticationSchemeLoader authenticationSchemeLoader)
		{
			this.AuthenticationOptions = authenticationOptions ?? throw new ArgumentNullException(nameof(authenticationOptions));
			this.AuthenticationSchemeLoader = authenticationSchemeLoader ?? throw new ArgumentNullException(nameof(authenticationSchemeLoader));
		}

		#endregion

		#region Properties

		protected internal virtual IOptions<ExtendedAuthenticationOptions> AuthenticationOptions { get; }
		protected internal virtual IAuthenticationSchemeLoader AuthenticationSchemeLoader { get; }

		#endregion

		#region Methods

		public virtual async Task<IActionResult> Index()
		{
			return await Task.FromResult(this.View());
		}

		[AllowAnonymous]
		public virtual async Task<IActionResult> SignIn(string returnUrl)
		{
			if(string.IsNullOrEmpty(returnUrl))
				returnUrl = "~/";

			if(!this.Url.IsLocalUrl(returnUrl))
				throw new InvalidOperationException("Invalid return-url.");

			var model = new SignInViewModel
			{
				ReturnUrl = returnUrl
			};

			var authenticationSchemes = (await this.AuthenticationSchemeLoader.ListAsync())
				.Where(item => item.Interactive && item.Kind != AuthenticationSchemeKind.Cookie)
				.OrderBy(item => item.Index)
				.ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase);

			foreach(var authenticationScheme in authenticationSchemes)
			{
				model.AuthenticationSchemes.Add(authenticationScheme);
			}

			return this.View(model);
		}

		[AllowAnonymous]
		public virtual async Task<IActionResult> SignOut(string signOutId)
		{
			if(this.User.Identity.IsAuthenticated)
				return this.View(new SignOutViewModel { Form = { Id = signOutId } });

			return await Task.FromResult(this.View("SignedOut"));
		}

		[AllowAnonymous]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public virtual async Task<IActionResult> SignOut(SignOutForm form)
		{
			var authenticationSchemeName = this.User.Claims.FindFirstIdentityProviderClaim()?.Value;

			if(this.User.Identity.IsAuthenticated)
				await this.HttpContext.SignOutAsync();

			// ReSharper disable InvertIf
			if(authenticationSchemeName != null)
			{
				var authenticationScheme = await this.AuthenticationSchemeLoader.GetAsync(authenticationSchemeName);

				if(authenticationScheme != null && authenticationScheme.SignOutSupport)
				{
					var url = this.Url.Action("SignOut", new { signOutId = form?.Id });

					return this.SignOut(new AuthenticationProperties { RedirectUri = url }, authenticationSchemeName);
				}
			}
			// ReSharper restore InvertIf

			return this.View("SignedOut");
		}

		#endregion
	}
}