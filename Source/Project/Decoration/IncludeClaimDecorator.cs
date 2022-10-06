using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Extensions;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <summary>
	/// Decorator that includes claims according to the patterns.
	/// Depending on the PrincipalClaimsAsSource property this decorator can either add filtered claims or filter existing claims.
	/// </summary>
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class IncludeClaimDecorator : FilterClaimDecorator
	{
		#region Constructors

		public IncludeClaimDecorator(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Methods

		protected internal override async Task FilterAsync(IClaimBuilderCollection claims)
		{
			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			await Task.CompletedTask.ConfigureAwait(false);

			if(claims.Any())
			{
				this.Logger.LogDebugIfEnabled($"Starting filtering with the following patterns: {string.Join(", ", this.Patterns.Select(pattern => pattern.ToStringRepresentation()))}");

				var claimsToIterate = claims.ToList();

				foreach(var claim in claimsToIterate)
				{
					var include = false;

					if(claim != null)
					{
						var claimType = claim.Type;

						// ReSharper disable All
						if(claimType != null)
						{
							include = this.Patterns.Any(pattern => claimType.Like(pattern));

							this.Logger.LogDebugIfEnabled($"Claim-type {claimType.ToStringRepresentation()} will{(include ? null : " NOT")} be included.");
						}
						else
						{
							this.Logger.LogDebugIfEnabled("The claim-type is null and will NOT be included.");
						}
						// ReSharper restore All
					}
					else
					{
						this.Logger.LogDebugIfEnabled("The claim is null and will NOT be included.");
					}

					if(!include)
						claims.Remove(claim);
				}
			}
			else
			{
				this.Logger.LogDebugIfEnabled("The claims collection is empty.");
			}
		}

		#endregion
	}
}