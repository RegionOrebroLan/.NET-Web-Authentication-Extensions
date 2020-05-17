using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using RegionOrebroLan.Web.Authentication.Configuration;

namespace RegionOrebroLan.Web.Authentication
{
	public class AuthenticationSchemeLoader : IAuthenticationSchemeLoader
	{
		#region Constructors

		public AuthenticationSchemeLoader(IAuthenticationSchemeProvider authenticationSchemeProvider, IOptions<ExtendedAuthenticationOptions> options)
		{
			this.AuthenticationSchemeProvider = authenticationSchemeProvider ?? throw new ArgumentNullException(nameof(authenticationSchemeProvider));
			this.Options = options ?? throw new ArgumentNullException(nameof(options));
		}

		#endregion

		#region Properties

		protected internal virtual IAuthenticationSchemeProvider AuthenticationSchemeProvider { get; }
		protected internal virtual IOptions<ExtendedAuthenticationOptions> Options { get; }

		#endregion

		#region Methods

		protected internal virtual IAuthenticationScheme Convert(AuthenticationScheme authenticationScheme)
		{
			// ReSharper disable InvertIf
			if(authenticationScheme != null)
			{
				this.Options.Value.SchemeRegistrations.TryGetValue(authenticationScheme.Name, out var schemeOptions);

				return new ExtendedAuthenticationScheme(authenticationScheme.DisplayName, authenticationScheme.HandlerType, authenticationScheme.Name, schemeOptions);
			}
			// ReSharper restore InvertIf

			return null;
		}

		protected internal virtual IEnumerable<IAuthenticationScheme> Convert(IEnumerable<AuthenticationScheme> authenticationSchemes)
		{
			return (authenticationSchemes ?? Enumerable.Empty<AuthenticationScheme>()).Select(this.Convert).Where(authenticationScheme => authenticationScheme != null);
		}

		public virtual async Task<IAuthenticationScheme> GetAsync(string name)
		{
			var authenticationScheme = await this.AuthenticationSchemeProvider.GetSchemeAsync(name).ConfigureAwait(false);

			return this.Convert(authenticationScheme);
		}

		public virtual async Task<IAuthenticationScheme> GetDefaultAsync()
		{
			var authenticationScheme = await this.AuthenticationSchemeProvider.GetDefaultAuthenticateSchemeAsync().ConfigureAwait(false);

			return this.Convert(authenticationScheme);
		}

		public virtual async Task<IAuthenticationScheme> GetDefaultChallengeAsync()
		{
			var authenticationScheme = await this.AuthenticationSchemeProvider.GetDefaultChallengeSchemeAsync().ConfigureAwait(false);

			return this.Convert(authenticationScheme);
		}

		public virtual async Task<IAuthenticationScheme> GetDefaultForbidAsync()
		{
			var authenticationScheme = await this.AuthenticationSchemeProvider.GetDefaultForbidSchemeAsync().ConfigureAwait(false);

			return this.Convert(authenticationScheme);
		}

		public virtual async Task<IAuthenticationScheme> GetDefaultSignInAsync()
		{
			var authenticationScheme = await this.AuthenticationSchemeProvider.GetDefaultSignInSchemeAsync().ConfigureAwait(false);

			return this.Convert(authenticationScheme);
		}

		public virtual async Task<IAuthenticationScheme> GetDefaultSignOutAsync()
		{
			var authenticationScheme = await this.AuthenticationSchemeProvider.GetDefaultSignOutSchemeAsync().ConfigureAwait(false);

			return this.Convert(authenticationScheme);
		}

		public virtual async Task<IEnumerable<IAuthenticationScheme>> ListAsync()
		{
			var authenticationSchemes = await this.AuthenticationSchemeProvider.GetAllSchemesAsync().ConfigureAwait(false);

			return this.Convert(authenticationSchemes);
		}

		public virtual async Task<IEnumerable<IAuthenticationScheme>> ListRequestHandlerAsync()
		{
			var authenticationSchemes = await this.AuthenticationSchemeProvider.GetRequestHandlerSchemesAsync().ConfigureAwait(false);

			return this.Convert(authenticationSchemes);
		}

		#endregion
	}
}