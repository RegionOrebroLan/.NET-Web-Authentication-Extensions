using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Security.Claims.Extensions;
using RegionOrebroLan.Web.Authentication.Security.Claims;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc />
	public abstract class AuthenticationDecorator : IAuthenticationDecorator
	{
		#region Constructors

		protected AuthenticationDecorator(ILoggerFactory loggerFactory)
		{
			if(loggerFactory == null)
				throw new ArgumentNullException(nameof(loggerFactory));

			this.Logger = loggerFactory.CreateLogger(this.GetType());
		}

		#endregion

		#region Properties

		public virtual bool AdjustIdentityProviderClaim { get; set; } = true;

		/// <summary>
		/// Will include the authentication-scheme as identity-provider-claim.
		/// </summary>
		public virtual bool IncludeAuthenticationSchemeAsIdentityProviderClaim { get; set; } = true;

		protected internal virtual ILogger Logger { get; }

		#endregion

		#region Methods

		protected internal virtual void AddAuthenticationSchemeAsIdentityProviderClaimIfNecessary(string authenticationScheme, IClaimBuilderCollection claims)
		{
			if(authenticationScheme == null)
				throw new ArgumentNullException(nameof(authenticationScheme));

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			if(!this.IncludeAuthenticationSchemeAsIdentityProviderClaim)
				return;

			var identityProviderClaim = claims.FindFirstIdentityProviderClaim();

			if(identityProviderClaim != null)
				return;

			claims.Add(ExtendedClaimTypes.IdentityProvider, authenticationScheme);
		}

		[SuppressMessage("Style", "IDE0016:Use 'throw' expression")]
		protected internal virtual void AdjustIdentityProviderClaimIfNecessary(string authenticationScheme, IClaimBuilderCollection claims)
		{
			if(authenticationScheme == null)
				throw new ArgumentNullException(nameof(authenticationScheme));

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			if(!this.AdjustIdentityProviderClaim)
				return;

			var identityProviderClaim = claims.FindFirstIdentityProviderClaim();

			if(identityProviderClaim == null)
				return;

			if(string.Equals(authenticationScheme, identityProviderClaim.Value, StringComparison.OrdinalIgnoreCase))
				return;

			identityProviderClaim.Value = authenticationScheme;
			identityProviderClaim.Issuer = identityProviderClaim.OriginalIssuer = null;
		}

		public virtual async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			this.AddAuthenticationSchemeAsIdentityProviderClaimIfNecessary(authenticationScheme, claims);

			this.AdjustIdentityProviderClaimIfNecessary(authenticationScheme, claims);

			await Task.CompletedTask.ConfigureAwait(false);
		}

		public virtual async Task InitializeAsync(IConfigurationSection optionsConfiguration)
		{
			optionsConfiguration?.Bind(this, binderOptions => { binderOptions.BindNonPublicProperties = true; });

			await Task.CompletedTask.ConfigureAwait(false);
		}

		protected internal virtual string ValueAsFormatArgument(string value)
		{
			return value != null ? $"\"{value}\"" : "null";
		}

		#endregion
	}
}