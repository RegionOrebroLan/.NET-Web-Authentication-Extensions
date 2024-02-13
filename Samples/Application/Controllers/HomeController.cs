using System;
using System.Linq;
using System.Threading.Tasks;
using Application.Models;
using Application.Models.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using RegionOrebroLan.Web.Authentication;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace Application.Controllers
{
	public class HomeController : Controller
	{
		#region Fields

		private static JsonSerializerSettings _jsonSerializerSettings;

		#endregion

		#region Constructors

		public HomeController(IAuthenticationSchemeLoader authenticationSchemeLoader)
		{
			this.AuthenticationSchemeLoader = authenticationSchemeLoader ?? throw new ArgumentNullException(nameof(authenticationSchemeLoader));
		}

		#endregion

		#region Properties

		protected internal virtual IAuthenticationSchemeLoader AuthenticationSchemeLoader { get; }

		protected internal virtual JsonSerializerSettings JsonSerializerSettings => _jsonSerializerSettings ??= new JsonSerializerSettings
		{
			ContractResolver = new ContractResolver(),
			Formatting = Formatting.Indented,
			NullValueHandling = NullValueHandling.Ignore,
			PreserveReferencesHandling = PreserveReferencesHandling.None,
			ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
		};

		#endregion

		#region Methods

		public virtual async Task<IActionResult> Index()
		{
			return await Task.FromResult(this.View());
		}

		public virtual async Task<IActionResult> Schemes()
		{
			var model = new HomeViewModel();

			foreach(var (authenticationScheme, options) in (await this.AuthenticationSchemeLoader.GetDiagnosticsAsync(this.HttpContext.RequestServices)).OrderBy(item => item.Key.Name))
			{
				var json = options != null ? JsonConvert.SerializeObject(options, this.JsonSerializerSettings) : null;

				model.AuthenticationSchemes.Add(authenticationScheme, json);
			}

			return await Task.FromResult(this.View(model));
		}

		#endregion
	}
}