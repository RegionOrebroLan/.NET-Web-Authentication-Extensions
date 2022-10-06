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

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc cref="Decorator" />
	/// <inheritdoc cref="IAuthenticationDecorator" />
	public abstract class FilterClaimDecorator : Decorator, IAuthenticationDecorator
	{
		#region Constructors

		protected FilterClaimDecorator(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		/// <summary>
		/// Patterns for filtering claim-types. The patterns can contain an explicit claim-type or a wildcard-pattern.
		/// </summary>
		public virtual ISet<string> Patterns { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		/// <summary>
		/// If false the claims parameter in the DecorateAsync method is used as source.
		/// If true the authenticateResult.Principal.Claims from the authenticateResult parameter in the DecorateAsync method is used as source.
		/// So if false we filter the claims parameter and if true we filter the authenticateResult.Principal.Claims and add them to the claims parameter.
		/// </summary>
		public virtual bool PrincipalClaimsAsSource { get; set; }

		#endregion

		#region Methods

		public virtual async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			try
			{
				if(authenticateResult == null)
					throw new ArgumentNullException(nameof(authenticateResult));

				if(claims == null)
					throw new ArgumentNullException(nameof(claims));

				if(this.PrincipalClaimsAsSource)
				{
					var principalClaims = new ClaimBuilderCollection();
					principalClaims.AddRange((authenticateResult.Principal?.Claims ?? Enumerable.Empty<Claim>()).Select(claim => new ClaimBuilder(claim)));

					await this.FilterAsync(principalClaims).ConfigureAwait(false);

					foreach(var claim in principalClaims)
					{
						claims.Add(claim);
					}
				}
				else
				{
					await this.FilterAsync(claims).ConfigureAwait(false);
				}
			}
			catch(Exception exception)
			{
				var message = $"Could not decorate authentication-scheme {authenticationScheme.ToStringRepresentation()}.";

				this.Logger.LogErrorIfEnabled(exception, message);

				throw new InvalidOperationException(message, exception);
			}
		}

		protected internal abstract Task FilterAsync(IClaimBuilderCollection claims);

		#endregion
	}
}