using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.Security.Claims;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc />
	public abstract class ExcludeClaimDecorator : AuthenticationDecorator
	{
		#region Constructors

		protected ExcludeClaimDecorator(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		protected internal virtual ISet<string> ClaimTypeExclusions { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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

			foreach(var claim in authenticateResult.Principal.Claims)
			{
				if(!this.ClaimTypeExclusions.Contains(claim.Type))
					claims.Add(new ClaimBuilder(claim));
			}

			await base.DecorateAsync(authenticateResult, authenticationScheme, claims, properties).ConfigureAwait(false);
		}

		#endregion
	}
}