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
using RegionOrebroLan.Web.Authentication.Extensions;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace Application.Controllers
{
	public class AuthenticateController : Controller
	{
		#region Fields

		private static readonly IDictionary<string, Tuple<string, string>> _uniqueIdentifierMap = new Dictionary<string, Tuple<string, string>>(StringComparer.OrdinalIgnoreCase);

		#endregion

		#region Constructors

		public AuthenticateController(IOptionsMonitor<ExtendedAuthenticationOptions> authenticationOptionsMonitor, IAuthenticationSchemeLoader authenticationSchemeLoader, IDecorationLoader decorationLoader, ILoggerFactory loggerFactory)
		{
			this.AuthenticationOptions = (authenticationOptionsMonitor ?? throw new ArgumentNullException(nameof(authenticationOptionsMonitor))).CurrentValue;
			this.AuthenticationSchemeLoader = authenticationSchemeLoader ?? throw new ArgumentNullException(nameof(authenticationSchemeLoader));
			this.DecorationLoader = decorationLoader ?? throw new ArgumentNullException(nameof(decorationLoader));

			if(loggerFactory == null)
				throw new ArgumentNullException(nameof(loggerFactory));

			this.Logger = loggerFactory.CreateLogger(this.GetType());
		}

		#endregion

		#region Properties

		protected internal virtual ExtendedAuthenticationOptions AuthenticationOptions { get; }
		protected internal virtual IAuthenticationSchemeLoader AuthenticationSchemeLoader { get; }
		protected internal virtual IDecorationLoader DecorationLoader { get; }
		protected internal virtual ILogger Logger { get; }
		protected internal virtual IDictionary<string, Tuple<string, string>> UniqueIdentifierMap => _uniqueIdentifierMap;

		#endregion

		#region Methods

		public virtual async Task<IActionResult> Callback()
		{
			var authenticateResult = await this.HttpContext.AuthenticateAsync(this.AuthenticationOptions.DefaultSignInScheme);

			if(!authenticateResult.Succeeded)
				throw new InvalidOperationException("Authentication error.", authenticateResult.Failure);

			var returnUrl = this.ResolveAndValidateReturnUrl(authenticateResult.Properties.Items["returnUrl"]);

			var authenticationProperties = new AuthenticationProperties();
			var authenticationScheme = authenticateResult.Properties.Items["scheme"];
			var claims = new ClaimBuilderCollection();
			var decorators = (await this.DecorationLoader.GetCallbackDecoratorsAsync(authenticationScheme)).ToArray();

			foreach(var decorator in decorators)
			{
				await decorator.DecorateAsync(authenticateResult, authenticationScheme, claims, authenticationProperties);
			}

			await this.ResolveUniqueIdentifier(authenticateResult, authenticationScheme, claims);
			await this.ResolveName(authenticateResult, claims);

			await this.HttpContext.SignInAsync(this.AuthenticationOptions.DefaultScheme, this.CreateClaimsPrincipal(authenticationScheme, claims), authenticationProperties);

			await this.HttpContext.SignOutAsync(this.AuthenticationOptions.DefaultSignInScheme);

			return this.Redirect(returnUrl);
		}

		public virtual async Task<IActionResult> Certificate(string authenticationScheme, string returnUrl)
		{
			this.ValidateAuthenticationScheme(authenticationScheme, AuthenticationSchemeKind.Certificate);

			returnUrl = this.ResolveAndValidateReturnUrl(returnUrl);

			var authenticateResult = await this.HttpContext.AuthenticateAsync(authenticationScheme);

			if(!authenticateResult.Succeeded)
				throw new InvalidOperationException("Authentication error.", authenticateResult.Failure);

			var authenticationProperties = this.CreateAuthenticationProperties(authenticationScheme, returnUrl);
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

			await this.HttpContext.SignInAsync(this.AuthenticationOptions.DefaultSignInScheme, certificatePrincipal, authenticationProperties);

			return this.Redirect(authenticationProperties.RedirectUri);
		}

		public virtual async Task<IActionResult> Cookie(string authenticationScheme, string returnUrl)
		{
			this.Logger.LogErrorIfEnabled("Cookie action called.");

			return await Task.FromResult(this.NotFound());
		}

		protected internal virtual AuthenticationProperties CreateAuthenticationProperties(string authenticationScheme, string returnUrl)
		{
			var authenticationProperties = new AuthenticationProperties
			{
				RedirectUri = this.Url.Action(nameof(this.Callback))
			};

			authenticationProperties.SetString(nameof(returnUrl), returnUrl);
			authenticationProperties.SetString("scheme", authenticationScheme);

			foreach(var decorator in this.DecorationLoader.GetAuthenticationPropertiesDecoratorsAsync(authenticationScheme).Result)
			{
				decorator.DecorateAsync(authenticationScheme, authenticationProperties, returnUrl);
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
			if(authenticateResult.Succeeded)
			{
				if(authenticateResult.Principal == null)
					throw new InvalidOperationException("Succeeded authenticate-result but the principal is null.");

				var authenticationProperties = this.CreateAuthenticationProperties(authenticationScheme, returnUrl);
				var claims = new ClaimBuilderCollection();
				var decorators = (await this.DecorationLoader.GetAuthenticationDecoratorsAsync(authenticationScheme)).ToArray();

				if(decorators.Any())
				{
					foreach(var decorator in decorators)
					{
						await decorator.DecorateAsync(authenticateResult, authenticationScheme, claims, authenticationProperties);
					}
				}
				else
				{
					var nameClaim = authenticateResult.Principal.Claims.FindFirstNameClaim();

					if(nameClaim != null)
						claims.Add(new ClaimBuilder(nameClaim));

					var uniqueIdentifierClaim = authenticateResult.Principal.Claims.FindFirst(this.AuthenticationOptions.Negotiate.UniqueIdentifierClaimType);

					if(uniqueIdentifierClaim == null)
						throw new InvalidOperationException($"Could not find an unique identifier claim. Claim-type uses as unique identifier claim-type is {this.AuthenticationOptions.Negotiate.UniqueIdentifierClaimType.ToStringRepresentation()}.");

					claims.Add(new ClaimBuilder { Type = ClaimTypes.NameIdentifier, Value = uniqueIdentifierClaim.Value });

					if(this.AuthenticationOptions.Negotiate.IncludeSecurityIdentifierClaim)
					{
						var securityIdentifierClaim = authenticateResult.Principal.Claims.FindFirst(ClaimTypes.PrimarySid);

						if(securityIdentifierClaim != null)
							claims.Add(new ClaimBuilder(securityIdentifierClaim));
					}

					if(this.AuthenticationOptions.Negotiate.IncludeNameClaimAsWindowsAccountNameClaim && nameClaim != null)
						claims.Add(new ClaimBuilder { Type = ClaimTypes.WindowsAccountName, Value = nameClaim.Value });

					if(this.AuthenticationOptions.Negotiate.Roles.Include)
					{
						/*
							If there are many roles we may get an error because we save the principal in the authentication-cookie:
							Bad Request - Request Too Long: HTTP Error 400. The size of the request headers is too long.

							You could handle that by implementing a CookieAuthenticationOptions.SessionStore (ITicketStore).
							In this sample we handle it by only including the top 10 roles.
						*/
						const int maximumNumberOfRoles = 10;
						var index = 0;
						var roles = new List<string>();

						foreach(var roleClaim in authenticateResult.Principal.Claims.Find(this.AuthenticationOptions.Negotiate.Roles.ClaimType))
						{
							if(index == maximumNumberOfRoles)
								break;

							var role = roleClaim.Value;

							if(this.AuthenticationOptions.Negotiate.Roles.Translate && OperatingSystem.IsWindows())
							{
								var securityIdentifier = new SecurityIdentifier(role);
								role = securityIdentifier.Translate(typeof(NTAccount)).Value;
							}

							roles.Add(role);

							index++;
						}

						roles.Sort();

						foreach(var role in roles)
						{
							claims.Add(new ClaimBuilder { Type = ClaimTypes.Role, Value = role });
						}
					}
				}

				await this.HttpContext.SignInAsync(this.AuthenticationOptions.DefaultSignInScheme, this.CreateClaimsPrincipal(authenticationScheme, claims), authenticationProperties);

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

			return await Task.FromResult(this.Challenge(this.CreateAuthenticationProperties(authenticationScheme, returnUrl), authenticationScheme));
		}

		protected internal virtual string ResolveAndValidateReturnUrl(string returnUrl)
		{
			if(string.IsNullOrEmpty(returnUrl))
				returnUrl = "~/";

			if(!this.Url.IsLocalUrl(returnUrl))
				throw new InvalidOperationException($"\"{returnUrl}\" is an invalid return-url.");

			return returnUrl;
		}

		protected internal virtual async Task ResolveName(AuthenticateResult authenticateResult, IClaimBuilderCollection claims)
		{
			if(authenticateResult == null)
				throw new ArgumentNullException(nameof(authenticateResult));

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			var nameClaim = claims.FindFirstNameClaim();

			if(nameClaim == null)
			{
				var principalNameClaim = authenticateResult.Principal.Claims.FindFirstNameClaim();

				if(principalNameClaim != null)
				{
					nameClaim = new ClaimBuilder(principalNameClaim);
					claims.Add(nameClaim);
				}
			}

			await Task.CompletedTask.ConfigureAwait(false);
		}

		protected internal virtual async Task ResolveUniqueIdentifier(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims)
		{
			if(authenticateResult == null)
				throw new ArgumentNullException(nameof(authenticateResult));

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			var uniqueIdentifierClaim = claims.FindFirstUniqueIdentifierClaim();

			if(uniqueIdentifierClaim == null)
			{
				var principalUniqueIdentifierClaim = authenticateResult.Principal.Claims.FindFirstUniqueIdentifierClaim();

				if(principalUniqueIdentifierClaim != null)
				{
					uniqueIdentifierClaim = new ClaimBuilder(principalUniqueIdentifierClaim);
					claims.Add(uniqueIdentifierClaim);
				}
			}

			if(uniqueIdentifierClaim == null)
				throw new InvalidOperationException($"There is no unique-identifier-claim for authentication-scheme \"{authenticationScheme}\".");

			var uniqueIdentifier = uniqueIdentifierClaim.Value;

			var identityProvider = claims.FindFirstIdentityProviderClaim()?.Value ?? authenticationScheme;

			uniqueIdentifierClaim.Value = this.GetOrCreateUniqueIdentifier(identityProvider, uniqueIdentifier);
			uniqueIdentifierClaim.Issuer = uniqueIdentifierClaim.OriginalIssuer = uniqueIdentifierClaim.ValueType = null;

			// We add the original unique identifier just for information.
			claims.Add(new ClaimBuilder { Type = "sub_at_the_provider", Value = uniqueIdentifier });

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