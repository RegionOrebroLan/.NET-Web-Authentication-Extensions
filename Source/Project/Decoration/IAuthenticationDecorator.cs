using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using RegionOrebroLan.Security.Claims;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	public interface IAuthenticationDecorator
	{
		#region Methods

		/// <summary>
		/// Decorate the authentication. Add, change or remove claims. Add, change or remove authentication-properties.
		/// </summary>
		/// <param name="authenticateResult">The current authenticate-result.</param>
		/// <param name="authenticationScheme">The authentication-scheme.</param>
		/// <param name="claims">The collection of claim-builders to decorate.</param>
		/// <param name="properties">The authentication-properties to decorate.</param>
		Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties);

		Task InitializeAsync(IConfigurationSection optionsConfiguration);

		#endregion
	}
}