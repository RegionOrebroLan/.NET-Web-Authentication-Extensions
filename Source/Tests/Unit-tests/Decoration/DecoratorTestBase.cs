using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;

namespace UnitTests.Decoration
{
	public abstract class DecoratorTestBase
	{
		#region Methods

		protected internal virtual async Task<AuthenticationTicket> CreateAuthenticationTicketAsync(AuthenticationProperties authenticationProperties = null, string authenticationScheme = null, IEnumerable<Claim> claims = null)
		{
			authenticationProperties ??= new AuthenticationProperties();

			return new AuthenticationTicket(await this.CreateClaimsPrincipalAsync(claims), authenticationProperties, authenticationScheme);
		}

		protected internal virtual async Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(IEnumerable<Claim> claims = null)
		{
			claims = (claims ?? Enumerable.Empty<Claim>()).ToArray();

			var claimsIdentity = new ClaimsIdentity(claims, "Test-authentication-type", JwtClaimTypes.Name, JwtClaimTypes.Role);

			return await Task.FromResult(new ClaimsPrincipal(claimsIdentity));
		}

		#endregion
	}
}