using System;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class CallbackDecorator : ExcludeClaimDecorator
	{
		#region Constructors

		public CallbackDecorator(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Methods

		public override async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			try
			{
				await base.DecorateAsync(authenticateResult, authenticationScheme, claims, properties).ConfigureAwait(false);

				if(authenticateResult == null)
					throw new ArgumentNullException(nameof(authenticateResult));

				if(properties == null)
					throw new ArgumentNullException(nameof(properties));

				// If the external provider issued an id_token, we'll keep it for sign-out.
				var identityToken = authenticateResult.Properties.GetTokenValue(OidcConstants.TokenTypes.IdentityToken);

				if(identityToken != null)
					properties.StoreTokens(new[] {new AuthenticationToken {Name = OidcConstants.TokenTypes.IdentityToken, Value = identityToken}});
			}
			catch(Exception exception)
			{
				const string message = "Could not decorate authentication-callback.";

				this.Logger.LogErrorIfEnabled(exception, message);

				throw new InvalidOperationException(message, exception);
			}
		}

		#endregion
	}
}