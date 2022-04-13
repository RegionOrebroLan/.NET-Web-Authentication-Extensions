using System;
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

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class OrganizationCallbackDecorator : ActiveDirectoryCallbackDecorator
	{
		#region Constructors

		public OrganizationCallbackDecorator(IActiveDirectory activeDirectory, ILoggerFactory loggerFactory) : base(activeDirectory, loggerFactory) { }

		#endregion

		#region Properties

		public override IdentifierKind IdentifierKind { get; set; } = IdentifierKind.SamAccountName;
		public virtual string IdentityClaimType { get; set; }
		public virtual string IdentityPrefix { get; set; }

		#endregion

		#region Methods

		public override async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			if(authenticateResult == null)
				throw new ArgumentNullException(nameof(authenticateResult));

			if(authenticateResult.Principal == null)
				throw new ArgumentException("The principal-property of the authenticate-result can not be null.", nameof(authenticateResult));

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

			var identityClaim = authenticateResult.Principal.FindFirst(this.IdentityClaimType);

			if(identityClaim == null)
			{
				this.Logger.LogWarningIfEnabled($"The claim {this.IdentityClaimType.ToStringRepresentation()} does not exist.");
				return;
			}

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

			var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, identity) }));

			authenticateResult = AuthenticateResult.Success(new AuthenticationTicket(principal, authenticationScheme));

			await base.DecorateAsync(authenticateResult, authenticationScheme, claims, properties).ConfigureAwait(false);
		}

		#endregion
	}
}