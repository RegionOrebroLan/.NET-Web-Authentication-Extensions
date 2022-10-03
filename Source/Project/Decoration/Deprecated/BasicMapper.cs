using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
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
	public abstract class BasicMapper : Decorator, IAuthenticationDecorator
	{
		#region Constructors

		protected BasicMapper(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		public virtual bool IgnoreExistingClaims { get; set; }
		public abstract IDictionary<string, string> Map { get; }

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

			var claimsPrincipal = authenticateResult.Principal ?? new ClaimsPrincipal(new ClaimsIdentity());

			foreach(var claim in claimsPrincipal.Claims)
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

				if(this.Map.TryGetValue(claimType, out var mappedClaimType) || this.Map.TryGetValue(urlEncodedColonClaimType, out mappedClaimType))
				{
					this.Logger.LogDebugIfEnabled($"Found mapped claim-type {mappedClaimType.ToStringRepresentation()} for claim-type {claimType.ToStringRepresentation()}.");

					if(this.IgnoreExistingClaims && claims.Any(item => string.Equals(mappedClaimType, item.Type, StringComparison.OrdinalIgnoreCase)))
					{
						this.Logger.LogDebugIfEnabled($"Ignoring claim-type {mappedClaimType.ToStringRepresentation()} because it already exists.");
						continue;
					}

					this.Logger.LogDebugIfEnabled($"Adding claim-type {mappedClaimType.ToStringRepresentation()} mapped from {claimType.ToStringRepresentation()}.");
					claims.Add(new ClaimBuilder(claim) {Type = mappedClaimType});
				}
				else
				{
					var details = claimType.Equals(urlEncodedColonClaimType, StringComparison.OrdinalIgnoreCase) ? $"The map does not contain {claimType.ToStringRepresentation()} as key." : $"The map contains neither {claimType.ToStringRepresentation()} nor {urlEncodedColonClaimType.ToStringRepresentation()} as key.";
					this.Logger.LogDebugIfEnabled($"Skipping claim-type {claimType.ToStringRepresentation()}. {details}");
				}
			}
		}

		#endregion
	}
}