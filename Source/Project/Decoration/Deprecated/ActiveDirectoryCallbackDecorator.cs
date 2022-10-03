using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.DirectoryServices;

namespace RegionOrebroLan.Web.Authentication.Decoration.Deprecated
{
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	[Obsolete(ObsoleteHelper.Message)]
	public class ActiveDirectoryCallbackDecorator : ActiveDirectoryDecorator
	{
		#region Constructors

		public ActiveDirectoryCallbackDecorator(IActiveDirectory activeDirectory, ILoggerFactory loggerFactory) : base(activeDirectory, loggerFactory) { }

		#endregion

		#region Properties

		public override bool AdjustIdentityProviderClaim { get; set; }
		public override IdentifierKind IdentifierKind { get; set; } = IdentifierKind.UserPrincipalNameWithEmailFallback;
		public override bool IncludeAuthenticationSchemeAsIdentityProviderClaim { get; set; }

		#endregion

		#region Methods

		public override async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			if(!claims.Any())
			{
				await base.DecorateAsync(authenticateResult, authenticationScheme, claims, properties).ConfigureAwait(false);
			}
			else
			{
				var activeDirectoryClaims = new ClaimBuilderCollection();

				await base.DecorateAsync(authenticateResult, authenticationScheme, activeDirectoryClaims, properties).ConfigureAwait(false);

				foreach(var activeDirectoryClaim in activeDirectoryClaims)
				{
					for(var i = 0; i < claims.Count; i++)
					{
						var claim = claims[i];

						if(!string.Equals(activeDirectoryClaim.Type, claim.Type, StringComparison.OrdinalIgnoreCase))
							continue;

						if(string.Equals(activeDirectoryClaim.Value, claim.Value, StringComparison.Ordinal))
							continue;

						claims[i] = activeDirectoryClaim;
					}
				}
			}
		}

		#endregion
	}
}