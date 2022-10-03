using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration.Deprecated
{
	/// <inheritdoc cref="Decorator" />
	/// <inheritdoc cref="IAuthenticationDecorator" />
	public abstract class BasicReplacer : Decorator, IAuthenticationDecorator
	{
		#region Constructors

		protected BasicReplacer(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		public abstract IDictionary<string, string> Replacements { get; }

		#endregion

		#region Methods

		public virtual async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			this.Logger.LogDebugIfEnabled($"DecorateAsync: authentication-scheme = {authenticationScheme.ToStringRepresentation()}, starting...");

			if(authenticateResult == null)
				throw new ArgumentNullException(nameof(authenticateResult));

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			foreach(var claim in claims)
			{
				// ReSharper disable All

				var claimType = claim?.Type;

				if(claimType == null)
				{
					this.Logger.LogDebugIfEnabled($"Skipping claim-type null.");
					continue;
				}

				// ReSharper restore All

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

		#endregion
	}
}