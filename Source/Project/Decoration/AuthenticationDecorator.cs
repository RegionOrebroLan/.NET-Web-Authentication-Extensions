using System;
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

		/// <summary>
		/// Will include the authentication-scheme as identity-provider-claim.
		/// </summary>
		protected internal virtual bool IncludeAuthenticationSchemeAsIdentityProviderClaim { get; set; } = true;

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

		public virtual async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			this.AddAuthenticationSchemeAsIdentityProviderClaimIfNecessary(authenticationScheme, claims);

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