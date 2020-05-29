using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	public interface IAuthenticationPropertiesDecorator : IDecorator
	{
		#region Methods

		/// <summary>
		/// Decorate the authentication-properties. Add, change or remove authentication-properties.
		/// </summary>
		/// <param name="authenticationScheme">The authentication-scheme.</param>
		/// <param name="properties">The authentication-properties to decorate.</param>
		/// <param name="returnUrl">The return-url.</param>
		[SuppressMessage("Design", "CA1054:Uri parameters should not be strings")]
		Task DecorateAsync(string authenticationScheme, AuthenticationProperties properties, string returnUrl);

		#endregion
	}
}