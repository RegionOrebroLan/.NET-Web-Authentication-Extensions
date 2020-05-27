using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc />
	public abstract class IncludeClaimDecorator : AuthenticationDecorator
	{
		#region Fields

		private const string _principalIdentityAuthenticationTypeSource = _principalIdentitySourcePrefix + "AuthenticationType";
		private const string _principalIdentitySourcePrefix = "Principal.Identity.";

		#endregion

		#region Constructors

		protected IncludeClaimDecorator(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		/// <summary>
		/// We use a dictionary only to be able to replace entries by configuration. The key is never used.
		/// </summary>
		public virtual IDictionary<string, ClaimMapping> ClaimInclusionsMap { get; } = new Dictionary<string, ClaimMapping>(StringComparer.OrdinalIgnoreCase);

		protected internal virtual string PrincipalIdentityAuthenticationTypeSource => _principalIdentityAuthenticationTypeSource;
		protected internal virtual string PrincipalIdentitySourcePrefix => _principalIdentitySourcePrefix;

		#endregion

		#region Methods

		public override async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			if(authenticateResult == null)
				throw new ArgumentNullException(nameof(authenticateResult));

			if(authenticateResult.Principal == null)
				throw new ArgumentException("The principal-property of the authenticate-result can not be null.", nameof(authenticateResult));

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			foreach(var mapping in this.ClaimInclusionsMap.Values)
			{
				if(!this.TryGetSpecialSourceClaim(authenticateResult.Principal, mapping.Source, out var claim))
				{
					var sourceClaim = this.GetSourceClaim(authenticateResult.Principal, mapping.Source);

					if(sourceClaim != null)
						claim = new ClaimBuilder(sourceClaim);
				}

				if(claim == null)
					continue;

				if(mapping.Destination != null)
					claim.Type = mapping.Destination;

				claims.Add(claim);
			}

			await base.DecorateAsync(authenticateResult, authenticationScheme, claims, properties).ConfigureAwait(false);
		}

		protected internal virtual Claim GetSourceClaim(ClaimsPrincipal principal, string source)
		{
			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			var claim = principal.Claims?.FirstOrDefault(item => string.Equals(item.Type, source, StringComparison.OrdinalIgnoreCase));

			if(claim == null)
				this.Logger.LogDebugIfEnabled($"Could not get source-claim for source {this.ValueAsFormatArgument(source)}.");

			return claim;
		}

		protected internal virtual bool TryGetSpecialSourceClaim(ClaimsPrincipal principal, string source, out IClaimBuilder claim)
		{
			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			claim = null;

			// ReSharper disable InvertIf
			if(!string.IsNullOrWhiteSpace(source) && source.StartsWith(this.PrincipalIdentitySourcePrefix, StringComparison.OrdinalIgnoreCase))
			{
				if(source.Equals(this.PrincipalIdentityAuthenticationTypeSource, StringComparison.OrdinalIgnoreCase))
				{
					claim = new ClaimBuilder
					{
						Type = source,
						Value = principal.Identity.AuthenticationType
					};

					var firstPrincipalClaim = principal.Claims?.FirstOrDefault();

					claim.Issuer = firstPrincipalClaim?.Issuer;
					claim.OriginalIssuer = firstPrincipalClaim?.OriginalIssuer;
				}
				else
				{
					this.Logger.LogDebugIfEnabled($"Could not get special source-claim for source {this.ValueAsFormatArgument(source)}.");
				}

				return true;
			}
			// ReSharper restore InvertIf

			return false;
		}

		#endregion
	}
}