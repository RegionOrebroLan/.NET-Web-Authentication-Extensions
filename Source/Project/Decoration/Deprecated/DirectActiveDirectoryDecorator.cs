using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.DirectoryServices;
using RegionOrebroLan.Web.Authentication.Extensions;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration.Deprecated
{
	/// <inheritdoc cref="Decorator" />
	/// <inheritdoc cref="IAuthenticationDecorator" />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	[Obsolete("This decorator is deprecated. Use RegionOrebroLan.Web.Authentication.Decoration.ActiveDirectoryDecorator instead.")]
	public class DirectActiveDirectoryDecorator : Decorator, IAuthenticationDecorator
	{
		#region Constructors

		public DirectActiveDirectoryDecorator(IActiveDirectory activeDirectory, ILoggerFactory loggerFactory) : base(loggerFactory)
		{
			this.ActiveDirectory = activeDirectory ?? throw new ArgumentNullException(nameof(activeDirectory));
		}

		#endregion

		#region Properties

		protected internal virtual IActiveDirectory ActiveDirectory { get; }
		public virtual string ActiveDirectoryClaimIssuer { get; set; } = "Active Directory";

		/// <summary>
		/// The claim-type used as identifier when querying the active-directory.
		/// </summary>
		public virtual string IdentifierClaimType { get; set; }

		public virtual IdentifierKind? IdentifierKind { get; set; }

		/// <summary>
		/// The attribute-to-claim map. The key is the active-directory attribute and the value is the claim-type.
		/// </summary>
		public virtual IDictionary<string, string> Map { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		public virtual bool ReplaceExistingClaims { get; set; }

		#endregion

		#region Methods

		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		public virtual async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			if(authenticateResult == null)
				throw new ArgumentNullException(nameof(authenticateResult));

			if(authenticateResult.Principal == null)
				throw new ArgumentException("The principal-property of the authenticate-result can not be null.", nameof(authenticateResult));

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			if(string.IsNullOrWhiteSpace(this.IdentifierClaimType))
			{
				this.Logger.LogWarningIfEnabled($"The identifier-claim-type is {this.IdentifierClaimType.ToStringRepresentation()}. The value is invalid.");
				return;
			}

			if(this.IdentifierKind == null)
			{
				this.Logger.LogWarningIfEnabled("The identifier-kind is null. The value is invalid.");
				return;
			}

			if(!this.Map.Any())
			{
				this.Logger.LogWarningIfEnabled("The map is empty.");
				return;
			}

			if(!this.TryGetIdentifier(authenticateResult, claims, out var identifier))
			{
				this.Logger.LogWarningIfEnabled($"Could not get identifier from identifier-claim-type {this.IdentifierClaimType.ToStringRepresentation()}. Identifier = {identifier.ToStringRepresentation()}.");
				return;
			}

			IDictionary<string, string> result;

			try
			{
				result = await this.ActiveDirectory.GetAttributesAsync(this.Map.Keys, identifier, this.IdentifierKind.Value).ConfigureAwait(false);
			}
			catch(Exception exception)
			{
				result = null;
				this.Logger.LogErrorIfEnabled(exception, $"Could not get Active-Directory attributes. Attributes: {string.Join(", ", this.Map.Keys)}.");
			}

			if(result == null || !result.Any())
				return;

			foreach(var (attribute, claimType) in this.Map)
			{
				if(!result.TryGetValue(attribute, out var value))
					continue;

				if(string.IsNullOrWhiteSpace(value))
					continue;

				var claim = claims.FindFirst(claimType);

				if(claim != null && !this.ReplaceExistingClaims)
					continue;

				var add = false;

				if(claim == null)
				{
					add = true;
					claim = new ClaimBuilder
					{
						Type = claimType
					};
				}

				claim.Issuer = this.ActiveDirectoryClaimIssuer;
				claim.Value = value;

				if(add)
					claims.Add(claim);
			}
		}

		protected internal virtual bool TryGetIdentifier(AuthenticateResult authenticateResult, IClaimBuilderCollection claims, out string identifier)
		{
			identifier = null;

			if(string.IsNullOrWhiteSpace(this.IdentifierClaimType))
				return false;

			IClaimBuilder identifierClaim = null;

			if(claims != null)
				identifierClaim = claims.FindFirst(this.IdentifierClaimType);

			if(identifierClaim == null && authenticateResult?.Principal?.Claims != null)
			{
				var claim = authenticateResult.Principal.Claims.FindFirst(this.IdentifierClaimType);

				if(claim != null)
					identifierClaim = new ClaimBuilder(claim);
			}

			identifier = identifierClaim?.Value;

			return !string.IsNullOrWhiteSpace(identifier);
		}

		#endregion
	}
}