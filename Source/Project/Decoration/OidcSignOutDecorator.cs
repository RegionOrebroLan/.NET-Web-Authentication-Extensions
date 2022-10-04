using System;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <summary>
	/// Decorator to be able to handle OpenId Connect (oidc) sign-out / single-sign-out. The decorator adds:
	/// - the authentication-scheme as an identity-provider claim (idp)
	/// - a session-id claim (sid) if it exists from the external oidc-provider
	/// - an identity-token (id_token) to the AuthenticationProperties if it exists from the external oidc-provider
	/// </summary>
	/// <inheritdoc cref="Decorator" />
	/// <inheritdoc cref="IAuthenticationDecorator" />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class OidcSignOutDecorator : Decorator, IAuthenticationDecorator
	{
		#region Constructors

		public OidcSignOutDecorator(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		public virtual string IdentityProviderClaimType { get; set; } = JwtClaimTypes.IdentityProvider;
		public virtual string IdentityTokenType { get; set; } = OidcConstants.TokenTypes.IdentityToken;
		public virtual string SessionIdClaimType { get; set; } = JwtClaimTypes.SessionId;

		#endregion

		#region Methods

		public virtual async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			try
			{
				if(authenticateResult == null)
					throw new ArgumentNullException(nameof(authenticateResult));

				if(authenticationScheme == null)
					throw new ArgumentNullException(nameof(authenticationScheme));

				if(claims == null)
					throw new ArgumentNullException(nameof(claims));

				if(properties == null)
					throw new ArgumentNullException(nameof(properties));

				claims.Add(new ClaimBuilder { Type = this.IdentityProviderClaimType, Value = authenticationScheme });
				this.Logger.LogDebugIfEnabled($"The authentication-scheme {authenticationScheme.ToStringRepresentation()} was added as an identity-provider-claim.");

				// If the external provider issued an id_token, we'll keep it for sign-out.
				var identityToken = authenticateResult.Properties.GetTokenValue(this.IdentityTokenType);

				if(identityToken != null)
				{
					properties.StoreTokens(new[] { new AuthenticationToken { Name = this.IdentityTokenType, Value = identityToken } });
					this.Logger.LogDebugIfEnabled("An identity-token was added.");
				}
				else
				{
					this.Logger.LogDebugIfEnabled("No identity-token to add.");
				}

				// If the external provider sent a session id claim, we'll copy it over for sign-out.
				var sessionIdClaim = authenticateResult.Principal.Claims.FirstOrDefault(claim => string.Equals(this.SessionIdClaimType, claim.Type, StringComparison.OrdinalIgnoreCase));

				if(sessionIdClaim != null)
				{
					claims.Add(new ClaimBuilder { Type = this.SessionIdClaimType, Value = sessionIdClaim.Value });
					this.Logger.LogDebugIfEnabled("A session-id-claim was added.");
				}
				else
				{
					this.Logger.LogDebugIfEnabled("No session-id-claim to add.");
				}
			}
			catch(Exception exception)
			{
				var message = $"Could not decorate authentication-scheme {authenticationScheme.ToStringRepresentation()}.";

				this.Logger.LogErrorIfEnabled(exception, message);

				throw new InvalidOperationException(message, exception);
			}
		}

		#endregion
	}
}