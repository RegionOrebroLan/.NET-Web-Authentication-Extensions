using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Security.Claims.Extensions;
using RegionOrebroLan.Web.Authentication.Configuration;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class WindowsAuthenticationDecorator : IncludeClaimDecorator
	{
		#region Fields

		private IDictionary<string, ClaimMapping> _claimInclusionsMap;

		#endregion

		#region Constructors

		public WindowsAuthenticationDecorator(IOptions<ExtendedAuthenticationOptions> authenticationOptions, ILoggerFactory loggerFactory) : base(loggerFactory)
		{
			this.AuthenticationOptions = authenticationOptions ?? throw new ArgumentNullException(nameof(authenticationOptions));
		}

		#endregion

		#region Properties

		protected internal virtual IOptions<ExtendedAuthenticationOptions> AuthenticationOptions { get; }

		public override IDictionary<string, ClaimMapping> ClaimInclusionsMap => this._claimInclusionsMap ??= new Dictionary<string, ClaimMapping>(StringComparer.OrdinalIgnoreCase)
		{
			{
				"AuthenticationMethod", new ClaimMapping
				{
					Destination = ClaimTypes.AuthenticationMethod,
					Source = this.PrincipalIdentityAuthenticationTypeSource
				}
			},
			{
				"Name", new ClaimMapping
				{
					Source = ClaimTypes.Name
				}
			},
			{
				"NameIdentifier", new ClaimMapping
				{
					Destination = ClaimTypes.NameIdentifier,
					Source = ClaimTypes.PrimarySid
				}
			},
			{
				"PrimarySid", new ClaimMapping
				{
					Source = ClaimTypes.PrimarySid
				}
			},
			{
				"WindowsAccountName", new ClaimMapping
				{
					Destination = ClaimTypes.WindowsAccountName,
					Source = ClaimTypes.Name
				}
			}
		};

		#endregion

		#region Methods

		public override async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			try
			{
				if(authenticateResult == null)
					throw new ArgumentNullException(nameof(authenticateResult));

				if(authenticateResult.Principal == null)
					throw new ArgumentException("The principal-property of the authenticate-result can not be null.", nameof(authenticateResult));

				if(!(authenticateResult.Principal is WindowsPrincipal))
					throw new ArgumentException("The principal is not a windows-principal.", nameof(authenticateResult));

				await base.DecorateAsync(authenticateResult, authenticationScheme, claims, properties).ConfigureAwait(false);

				if(this.AuthenticationOptions.Value.Windows.IncludeRoleClaims)
				{
					if(!(authenticateResult.Principal.Identity is WindowsIdentity windowsIdentity))
					{
						this.Logger.LogWarningIfEnabled("The principal-identity is not a windows-identity. Roles will not be added as claims.");
						return;
					}

					// ReSharper disable All
					foreach(var role in windowsIdentity.Groups.Translate(typeof(NTAccount)).Cast<NTAccount>().Select(ntAccount => ntAccount.Value).OrderBy(value => value))
					{
						claims.Add(authenticationScheme, ClaimTypes.Role, role, ClaimValueTypes.String);
					}
					// ReSharper restore All
				}
			}
			catch(Exception exception)
			{
				const string message = "Could not decorate windows-authentication.";

				this.Logger.LogErrorIfEnabled(exception, message);

				throw new InvalidOperationException(message, exception);
			}
		}

		#endregion
	}
}