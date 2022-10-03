using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
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
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	[Obsolete(ObsoleteHelper.Message)]
	public class OrganizationCallbackDecorator : ActiveDirectoryDecorator
	{
		#region Fields

		private IDictionary<string, ClaimMapping> _claimInclusionsMap;

		#endregion

		#region Constructors

		public OrganizationCallbackDecorator(IActiveDirectory activeDirectory, ILoggerFactory loggerFactory) : base(activeDirectory, loggerFactory) { }

		#endregion

		#region Properties

		public override IDictionary<string, ClaimMapping> ClaimInclusionsMap => this._claimInclusionsMap ??= new Dictionary<string, ClaimMapping>(StringComparer.OrdinalIgnoreCase)
		{
			{
				"Email", new ClaimMapping
				{
					Destination = ClaimTypes.Email,
					Source = this.ActiveDirectoryEmailAttributeName
				}
			},
			{
				"UserPrincipalName", new ClaimMapping
				{
					Destination = ClaimTypes.Upn,
					Source = this.ActiveDirectoryUserPrincipalNameAttributeName
				}
			}
		};

		public override IdentifierKind IdentifierKind { get; set; } = IdentifierKind.SamAccountName;
		public virtual string IdentityClaimType { get; set; }
		public virtual string IdentityPrefix { get; set; }
		public virtual bool ReplaceExistingClaims { get; set; } = true;

		#endregion

		#region Methods

		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		public override async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			if(authenticateResult == null)
				throw new ArgumentNullException(nameof(authenticateResult));

			if(authenticateResult.Principal == null)
				throw new ArgumentException("The principal-property of the authenticate-result can not be null.", nameof(authenticateResult));

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			if(string.IsNullOrWhiteSpace(this.IdentityClaimType))
			{
				this.Logger.LogWarningIfEnabled($"The identity-claim-type is {this.IdentityClaimType.ToStringRepresentation()}. The value is invalid.");
				return;
			}

			if(string.IsNullOrWhiteSpace(this.IdentityPrefix))
			{
				this.Logger.LogWarningIfEnabled($"The identity-prefix is {this.IdentityClaimType.ToStringRepresentation()}. The value is invalid.");
				return;
			}

			var identityClaim = claims.FindFirst(this.IdentityClaimType);
			var principalIdentityClaim = authenticateResult.Principal.FindFirst(this.IdentityClaimType);

			if(identityClaim == null && principalIdentityClaim == null)
			{
				this.Logger.LogWarningIfEnabled($"The claim {this.IdentityClaimType.ToStringRepresentation()} does not exist.");
				return;
			}

			identityClaim ??= new ClaimBuilder(principalIdentityClaim);

			if(string.IsNullOrWhiteSpace(identityClaim.Value))
			{
				this.Logger.LogWarningIfEnabled($"The claim {this.IdentityClaimType.ToStringRepresentation()} has a value of {identityClaim.Value.ToStringRepresentation()}. The value is invalid.");
				return;
			}

			if(!identityClaim.Value.StartsWith(this.IdentityPrefix, StringComparison.OrdinalIgnoreCase))
			{
				this.Logger.LogWarningIfEnabled($"The claim {this.IdentityClaimType.ToStringRepresentation()} has a value of {identityClaim.Value.ToStringRepresentation()}. The value does not start with {this.IdentityPrefix.ToStringRepresentation()}. The value is invalid.");
				return;
			}

			var identity = identityClaim.Value.Substring(this.IdentityPrefix.Length);

			if(string.IsNullOrWhiteSpace(identity))
			{
				this.Logger.LogWarningIfEnabled($"The identity has a value of {identity.ToStringRepresentation()}. The value is invalid.");
				return;
			}

			var map = this.ClaimInclusionsMap.Values.Where(mapping => !string.IsNullOrWhiteSpace(mapping.Source)).ToArray();

			var attributes = map.Select(mapping => mapping.Source).ToHashSet(StringComparer.OrdinalIgnoreCase);

			if(!attributes.Any())
			{
				this.Logger.LogWarningIfEnabled("No Active-Directory attributes to request.");
				return;
			}

			IDictionary<string, string> result;

			try
			{
				result = await this.ActiveDirectory.GetAttributesAsync(attributes, identity, this.IdentifierKind).ConfigureAwait(false);
			}
			catch(Exception exception)
			{
				result = null;
				this.Logger.LogErrorIfEnabled(exception, $"Could not get Active-Directory attributes. Attributes: {string.Join(", ", attributes)}.");
			}

			if(result == null || !result.Any())
				return;

			foreach(var mapping in map)
			{
				if(!result.TryGetValue(mapping.Source, out var value))
					continue;

				if(string.IsNullOrWhiteSpace(value))
					continue;

				var claim = claims.FindFirst(mapping.Destination);

				if(claim != null && !this.ReplaceExistingClaims)
					continue;

				var add = false;

				if(claim == null)
				{
					add = true;
					claim = new ClaimBuilder
					{
						Type = mapping.Destination
					};
				}

				claim.Issuer = this.ActiveDirectoryClaimIssuer;
				claim.Value = value;

				if(add)
					claims.Add(claim);
			}
		}

		#endregion
	}
}