using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <summary>
	/// Decorator that change the claim-type for the already decorated claims according to the replacements-dictionary property.
	/// </summary>
	/// <inheritdoc cref="Decorator" />
	/// <inheritdoc cref="IAuthenticationDecorator" />
	public class ReplacementDecorator : Decorator, IAuthenticationDecorator
	{
		#region Constructors

		public ReplacementDecorator(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		/// <summary>
		/// A dictionary with replacements. The key is the claim-type to replace, the value is the claim-type to replace with. A dictionary-key can not contain colons when configured in appsettings.json. So if we want to configure the replacement of "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", in appsettings.json, the key need to be "http%3a//schemas.xmlsoap.org/ws/2005/05/identity/claims/name".
		/// </summary>
		public virtual IDictionary<string, string> Replacements { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		#endregion

		#region Methods

		public virtual async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			try
			{
				if(claims == null)
					throw new ArgumentNullException(nameof(claims));

				foreach(var claim in claims)
				{
					var claimType = claim?.Type;

					if(claimType == null)
					{
						this.Logger.LogDebugIfEnabled("Skipping claim-type null.");
						continue;
					}

					var urlEncodedColonClaimType = claimType.UrlEncodeColon();

					if(this.Replacements.TryGetValue(claimType, out var replacementClaimType) || this.Replacements.TryGetValue(urlEncodedColonClaimType, out replacementClaimType))
					{
						this.Logger.LogDebugIfEnabled($"Replacing claim-type {claimType.ToStringRepresentation()} with claim-type {replacementClaimType.ToStringRepresentation()}.");
						claim.Type = replacementClaimType;
					}
					else
					{
						var details = claimType.Equals(urlEncodedColonClaimType, StringComparison.OrdinalIgnoreCase) ? $"The replacements does not contain {claimType.ToStringRepresentation()} as key." : $"The replacements contains neither {claimType.ToStringRepresentation()} nor {urlEncodedColonClaimType.ToStringRepresentation()} as key.";
						this.Logger.LogDebugIfEnabled($"Skipping claim-type {claimType.ToStringRepresentation()}. {details}");
					}
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