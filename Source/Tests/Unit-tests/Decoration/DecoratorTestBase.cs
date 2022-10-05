using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;

namespace UnitTests.Decoration
{
	public abstract class DecoratorTestBase
	{
		#region Fields

		private static string _resourceDirectoryPath;

		#endregion

		#region Properties

		protected internal virtual string ResourceDirectoryPath => _resourceDirectoryPath ??= Path.Combine(new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory).Parent.Parent.Parent.FullName, @"Decoration\Resources", this.GetType().Name);

		#endregion

		#region Methods

		protected internal virtual async Task<AuthenticationTicket> CreateAuthenticationTicketAsync(AuthenticationProperties authenticationProperties = null, string authenticationScheme = null, IEnumerable<Claim> claims = null)
		{
			authenticationProperties ??= new AuthenticationProperties();

			return new AuthenticationTicket(await this.CreateClaimsPrincipalAsync(claims), authenticationProperties, authenticationScheme);
		}

		protected internal virtual async Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(IEnumerable<Claim> claims = null)
		{
			claims = (claims ?? Enumerable.Empty<Claim>()).ToArray();

			var claimsIdentity = new ClaimsIdentity(claims, "Test-authentication-type", JwtClaimTypes.Name, JwtClaimTypes.Role);

			return await Task.FromResult(new ClaimsPrincipal(claimsIdentity));
		}

		protected internal virtual async Task<IConfiguration> CreateConfigurationAsync(string fileName)
		{
			var filePath = Path.Combine(this.ResourceDirectoryPath, $"{fileName}.json");

			var configurationBuilder = new ConfigurationBuilder();

			configurationBuilder.AddJsonFile(filePath);

			var configuration = configurationBuilder.Build();

			return await Task.FromResult(configuration);
		}

		#endregion
	}
}