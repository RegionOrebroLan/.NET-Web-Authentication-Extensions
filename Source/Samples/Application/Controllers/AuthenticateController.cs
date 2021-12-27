using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace Application.Controllers
{
	public class AuthenticateController : Controller
	{
		#region Fields

		private static readonly IDictionary<string, Tuple<string, string>> _uniqueIdentifierMap = new Dictionary<string, Tuple<string, string>>(StringComparer.OrdinalIgnoreCase);

		#endregion

		#region Constructors

		public AuthenticateController(IOptions<ExtendedAuthenticationOptions> authenticationOptions, IAuthenticationSchemeLoader authenticationSchemeLoader, IDecorationLoader decorationLoader, ILoggerFactory loggerFactory)
		{
			this.AuthenticationOptions = authenticationOptions ?? throw new ArgumentNullException(nameof(authenticationOptions));
			this.AuthenticationSchemeLoader = authenticationSchemeLoader ?? throw new ArgumentNullException(nameof(authenticationSchemeLoader));
			this.DecorationLoader = decorationLoader ?? throw new ArgumentNullException(nameof(decorationLoader));

			if(loggerFactory == null)
				throw new ArgumentNullException(nameof(loggerFactory));

			this.Logger = loggerFactory.CreateLogger(this.GetType());
		}

		#endregion

		#region Properties

		protected internal virtual IOptions<ExtendedAuthenticationOptions> AuthenticationOptions { get; }
		protected internal virtual IAuthenticationSchemeLoader AuthenticationSchemeLoader { get; }
		protected internal virtual IDecorationLoader DecorationLoader { get; }
		protected internal virtual ILogger Logger { get; }
		protected internal virtual IDictionary<string, Tuple<string, string>> UniqueIdentifierMap => _uniqueIdentifierMap;

		#endregion

		#region Methods

		public virtual async Task<IActionResult> Callback()
		{
			var authenticateResult = await this.HttpContext.AuthenticateAsync(this.AuthenticationOptions.Value.DefaultSignInScheme);

			if(!authenticateResult.Succeeded)
				throw new InvalidOperationException("Authentication error.", authenticateResult.Failure);

			var returnUrl = this.ResolveAndValidateReturnUrl(authenticateResult.Properties.Items["returnUrl"]);

			var authenticationScheme = authenticateResult.Properties.Items["scheme"];
			var decorators = (await this.DecorationLoader.GetCallbackDecoratorsAsync(authenticationScheme)).ToArray();

			if(!decorators.Any())
				throw new InvalidOperationException($"There are no callback-decorators for authentication-scheme \"{authenticationScheme}\".");

			var authenticationProperties = new AuthenticationProperties();
			var claims = new ClaimBuilderCollection();

			foreach(var decorator in decorators)
			{
				await decorator.DecorateAsync(authenticateResult, authenticationScheme, claims, authenticationProperties);
			}

			await this.ResolveUniqueIdentifier(authenticationScheme, claims);

			await this.HttpContext.SignInAsync(this.AuthenticationOptions.Value.DefaultScheme, this.CreateClaimsPrincipal(authenticationScheme, claims), authenticationProperties);

			await this.HttpContext.SignOutAsync(this.AuthenticationOptions.Value.DefaultSignInScheme);

			return this.Redirect(returnUrl);
		}

		public virtual async Task<IActionResult> Certificate(string authenticationScheme, string returnUrl)
		{
			this.ValidateAuthenticationScheme(authenticationScheme, AuthenticationSchemeKind.Certificate);

			returnUrl = this.ResolveAndValidateReturnUrl(returnUrl);

			var authenticateResult = await this.HttpContext.AuthenticateAsync(authenticationScheme);

			if(!authenticateResult.Succeeded)
				throw new InvalidOperationException("Authentication error.", authenticateResult.Failure);

			var authenticationProperties = this.CreateAuthenticationProperties(returnUrl, authenticationScheme);
			var certificatePrincipal = authenticateResult.Principal;
			var decorators = (await this.DecorationLoader.GetAuthenticationDecoratorsAsync(authenticationScheme)).ToArray();

			if(decorators.Any())
			{
				var claims = new ClaimBuilderCollection();

				foreach(var decorator in decorators)
				{
					await decorator.DecorateAsync(authenticateResult, authenticationScheme, claims, authenticationProperties);
				}

				certificatePrincipal = this.CreateClaimsPrincipal(authenticationScheme, claims);
			}

			await this.HttpContext.SignInAsync(this.AuthenticationOptions.Value.DefaultSignInScheme, certificatePrincipal, authenticationProperties);

			return this.Redirect(authenticationProperties.RedirectUri);
		}

		public virtual async Task<IActionResult> Cookie(string authenticationScheme, string returnUrl)
		{
			this.Logger.LogErrorIfEnabled("Cookie action called.");

			return await Task.FromResult(this.NotFound());
		}

		protected internal virtual AuthenticationProperties CreateAuthenticationProperties(string returnUrl, string scheme)
		{
			var authenticationProperties = new AuthenticationProperties
			{
				RedirectUri = this.Url.Action(nameof(this.Callback))
			};

			authenticationProperties.SetString(nameof(returnUrl), returnUrl);
			authenticationProperties.SetString(nameof(scheme), scheme);

			foreach(var decorator in this.DecorationLoader.GetAuthenticationPropertiesDecoratorsAsync(scheme).Result)
			{
				decorator.DecorateAsync(scheme, authenticationProperties, returnUrl);
			}

			return authenticationProperties;
		}

		protected internal virtual ClaimsPrincipal CreateClaimsPrincipal(string authenticationScheme, IClaimBuilderCollection claims)
		{
			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			return new ClaimsPrincipal(new ClaimsIdentity(claims.Build(), authenticationScheme, claims.FindFirstNameClaim()?.Type, null));
		}

		protected internal virtual string GetOrCreateUniqueIdentifier(string authenticationScheme, string remoteUniqueIdentifier)
		{
			foreach(var (key, (provider, identifier)) in this.UniqueIdentifierMap)
			{
				if(string.Equals(provider, authenticationScheme, StringComparison.OrdinalIgnoreCase) && string.Equals(identifier, remoteUniqueIdentifier, StringComparison.OrdinalIgnoreCase))
					return key;
			}

			var uniqueIdentifier = Guid.NewGuid().ToString();

			this.UniqueIdentifierMap.Add(uniqueIdentifier, new Tuple<string, string>(authenticationScheme, remoteUniqueIdentifier));

			return uniqueIdentifier;
		}

		public virtual async Task<IActionResult> Negotiate(string authenticationScheme, string returnUrl)
		{
			this.ValidateAuthenticationScheme(authenticationScheme, AuthenticationSchemeKind.Negotiate);

			returnUrl = this.ResolveAndValidateReturnUrl(returnUrl);

			// Check if negotiate-authentication has already been requested and succeeded.
			var authenticateResult = await this.HttpContext.AuthenticateAsync(authenticationScheme);

			// ReSharper disable All
			if(authenticateResult?.Principal is WindowsPrincipal)
			{
				var decorators = (await this.DecorationLoader.GetAuthenticationDecoratorsAsync(authenticationScheme)).ToArray();

				if(!decorators.Any())
					throw new InvalidOperationException($"There are no authentication-decorators for authentication-scheme \"{authenticationScheme}\".");

				var authenticationProperties = this.CreateAuthenticationProperties(returnUrl, authenticationScheme);
				var claims = new ClaimBuilderCollection();

				foreach(var decorator in decorators)
				{
					await decorator.DecorateAsync(authenticateResult, authenticationScheme, claims, authenticationProperties);
				}

				await this.HttpContext.SignInAsync(this.AuthenticationOptions.Value.DefaultSignInScheme, this.CreateClaimsPrincipal(authenticationScheme, claims), authenticationProperties);

				return this.Redirect(authenticationProperties.RedirectUri);
			}
			// ReSharper restore All

			// Trigger negotiate-authentication. Since negotiate-authentication don't support the redirect uri, this URL is re-triggered when we call challenge.
			return this.Challenge(authenticationScheme);
		}

		public virtual async Task<IActionResult> Remote(string authenticationScheme, string returnUrl)
		{
			this.ValidateAuthenticationScheme(authenticationScheme, AuthenticationSchemeKind.Remote);

			returnUrl = this.ResolveAndValidateReturnUrl(returnUrl);

			return await Task.FromResult(this.Challenge(this.CreateAuthenticationProperties(returnUrl, authenticationScheme), authenticationScheme));
		}

		protected internal virtual string ResolveAndValidateReturnUrl(string returnUrl)
		{
			if(string.IsNullOrEmpty(returnUrl))
				returnUrl = "~/";

			if(!this.Url.IsLocalUrl(returnUrl))
				throw new InvalidOperationException($"\"{returnUrl}\" is an invalid return-url.");

			return returnUrl;
		}

		protected internal virtual async Task ResolveUniqueIdentifier(string authenticationScheme, IClaimBuilderCollection claims)
		{
			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			var uniqueIdentifierClaim = claims.FindFirstUniqueIdentifierClaim();

			if(uniqueIdentifierClaim == null)
				throw new InvalidOperationException($"There is no unique-identifier-claim for authentication-scheme \"{authenticationScheme}\".");

			var identityProvider = claims.FindFirstIdentityProviderClaim()?.Value ?? authenticationScheme;

			uniqueIdentifierClaim.Value = this.GetOrCreateUniqueIdentifier(identityProvider, uniqueIdentifierClaim.Value);
			uniqueIdentifierClaim.Issuer = uniqueIdentifierClaim.OriginalIssuer = uniqueIdentifierClaim.ValueType = null;

			await Task.CompletedTask.ConfigureAwait(false);
		}

		public virtual async Task<IActionResult> Undefined(string authenticationScheme, string returnUrl)
		{
			this.Logger.LogErrorIfEnabled("Undefined action called.");

			return await Task.FromResult(this.NotFound());
		}

		protected internal virtual void ValidateAuthenticationScheme(string authenticationSchemeName, AuthenticationSchemeKind kind)
		{
			if(authenticationSchemeName == null)
				throw new ArgumentNullException(nameof(authenticationSchemeName));

			var authenticationScheme = this.AuthenticationSchemeLoader.GetAsync(authenticationSchemeName).Result;

			if(authenticationScheme == null)
				throw new InvalidOperationException($"The authentication-scheme \"{authenticationSchemeName}\" does not exist.");

			if(!authenticationScheme.Enabled)
				throw new InvalidOperationException($"The authentication-scheme \"{authenticationSchemeName}\" is not enabled.");

			if(!authenticationScheme.Interactive)
				throw new InvalidOperationException($"The authentication-scheme \"{authenticationSchemeName}\" is not interactive.");

			if(authenticationScheme.Kind != kind)
				throw new InvalidOperationException($"The authentication-scheme \"{authenticationSchemeName}\" is not of kind \"{kind}\".");
		}

		#endregion
	}
}