using System;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Security.Claims.Extensions;
using RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions;
using RegionOrebroLan.Web.Authentication.DirectoryServices;

namespace IntegrationTests.DirectoryServices
{
	[TestClass]
	public class ActiveDirectoryTest
	{
		#region Fields

		private static ActiveDirectory _activeDirectory;
		private static IServiceProvider _serviceProvider;

		#endregion

		#region Properties

		protected internal virtual ActiveDirectory ActiveDirectory => _activeDirectory ??= (ActiveDirectory)this.ServiceProvider.GetRequiredService<IActiveDirectory>();

		protected internal virtual IServiceProvider ServiceProvider
		{
			get
			{
				// ReSharper disable InvertIf
				if(_serviceProvider == null)
				{
					var services = Global.CreateServices();

					services.AddAuthentication(Global.CreateCertificateResolver(), Global.Configuration, new InstanceFactory());

					_serviceProvider = services.BuildServiceProvider();
				}
				// ReSharper restore InvertIf

				return _serviceProvider;
			}
		}

		#endregion

		#region Methods

		[TestMethod]
		public async Task ConnectionString_WithDefaultPort_Test()
		{
			await this.ConnectionStringTest("ConnectionString-With-Default-Port", AuthType.Ntlm, await this.GetSystemDomainFirstPartAsync(), 389);
		}

		[TestMethod]
		public async Task ConnectionString_WithoutPort_Test()
		{
			await this.ConnectionStringTest("ConnectionString-Without-Port", AuthType.Negotiate, IPGlobalProperties.GetIPGlobalProperties().DomainName, null);
		}

		[TestMethod]
		[SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase")]
		public async Task ConnectionString_WithSecurePort_Test()
		{
			await this.ConnectionStringTest("ConnectionString-With-Secure-Port", AuthType.Kerberos, (await this.GetSystemDomainFirstPartAsync()).ToLowerInvariant(), 636);
		}

		protected internal virtual async Task ConnectionStringTest(string appSettingsIdentifier, AuthType authenticationType, string domain, int? port)
		{
			await using(var stream = this.GetAppSettingsStream(appSettingsIdentifier, domain))
			{
				var serviceProvider = this.CreateServiceProvider(stream);

				var activeDirectory = (ActiveDirectory)serviceProvider.GetRequiredService<IActiveDirectory>();

				Assert.IsNotNull(activeDirectory);

				Assert.AreEqual(authenticationType, activeDirectory.LdapConnectionOptions.AuthenticationType);
				Assert.AreEqual(domain, activeDirectory.LdapConnectionOptions.DirectoryIdentifier.Servers.First());
				Assert.AreEqual(port, activeDirectory.LdapConnectionOptions.DirectoryIdentifier.Port);

				var windowsAccountName = WindowsIdentity.GetCurrent().Name;
				var samAccountName = windowsAccountName.Split('\\').Last();

				var identifier = windowsAccountName;
				var attributes = (await activeDirectory.GetAttributesAsync(new[] { "sAMAccountName" }, identifier, IdentifierKind.WindowsAccountName)).ToArray();
				Assert.AreEqual(1, attributes.Length);
				Assert.AreEqual("sAMAccountName", attributes.ElementAt(0).Key);

				identifier = samAccountName;
				attributes = (await activeDirectory.GetAttributesAsync(new[] { "sAMAccountName" }, identifier, IdentifierKind.SamAccountName)).ToArray();
				Assert.AreEqual(1, attributes.Length);
				Assert.AreEqual("sAMAccountName", attributes.ElementAt(0).Key);

				// Invalid domain-part
				identifier = $"{Guid.NewGuid()}\\{samAccountName}";
				attributes = (await activeDirectory.GetAttributesAsync(new[] { "sAMAccountName" }, identifier, IdentifierKind.SamAccountName)).ToArray();
				Assert.IsFalse(attributes.Any());
			}
		}

		protected internal virtual IServiceProvider CreateServiceProvider(Stream jsonStream)
		{
			var configurationBuilder = Global.CreateConfigurationBuilder();
			configurationBuilder.AddJsonStream(jsonStream);
			var configuration = configurationBuilder.Build();
			var services = Global.CreateServices(configuration);
			services.AddAuthentication(Global.CreateCertificateResolver(), configuration, new InstanceFactory());

			return services.BuildServiceProvider();
		}

		protected internal virtual string GetAppSettingsContent(string appSettingsIdentifier, params string[] formatArguments)
		{
			var path = Path.Combine(Global.ProjectDirectoryPath, "DirectoryServices", "Resources", "ActiveDirectory", $"appsettings.{appSettingsIdentifier}.json");

			var content = File.ReadAllText(path);

			formatArguments ??= Array.Empty<string>();

			for(var i = 0; i < formatArguments.Length; i++)
			{
				content = content.Replace($"{{{i}}}", formatArguments[i], StringComparison.OrdinalIgnoreCase);
			}

			return content;
		}

		protected internal virtual Stream GetAppSettingsStream(string appSettingsIdentifier, params string[] formatArguments)
		{
			var content = this.GetAppSettingsContent(appSettingsIdentifier, formatArguments);

			var bytes = Encoding.UTF8.GetBytes(content);

			return new MemoryStream(bytes);
		}

		[TestMethod]
		public void GetAttributesAsync_WithIdentifierParameter_IfTheIdentifierKindParameterIsSamAccountName_ShouldWorkProperly()
		{
			var identityNameParts = WindowsIdentity.GetCurrent().Name.Split('\\', 2);
			string samAccountName = null;
			if(identityNameParts.Length == 2)
				samAccountName = identityNameParts[1];

			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { "userPrincipalName" }, samAccountName, IdentifierKind.SamAccountName).Result;

			Assert.AreEqual(1, attributes.Count, "The test must be run on a domain.");
		}

		[TestMethod]
		public void GetAttributesAsync_WithIdentifierParameter_IfTheIdentifierKindParameterIsSecurityIdentifier_ShouldWorkProperly()
		{
			var identifier = new WindowsPrincipal(WindowsIdentity.GetCurrent()).FindFirst(ClaimTypes.PrimarySid)?.Value;

			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { "userPrincipalName" }, identifier, IdentifierKind.SecurityIdentifier).Result;

			Assert.AreEqual(1, attributes.Count, "The test must be run on a domain.");
		}

		[TestMethod]
		public void GetAttributesAsync_WithIdentifierParameter_IfTheIdentifierKindParameterIsUserPrincipalNameOrEmail_ShouldWorkProperly()
		{
			const string userPrincipalNameAttributeName = "userPrincipalName";
			const string samAccountNameAttributeName = "sAMAccountName";
			var claims = new ClaimsPrincipalBuilder(new WindowsPrincipal(WindowsIdentity.GetCurrent())).ClaimsIdentityBuilders.First().ClaimBuilders;
			var samAccountName = claims.First(claim => string.Equals(ClaimTypes.Name, claim.Type, StringComparison.OrdinalIgnoreCase)).Value.Split('\\').Last();
			var userPrincipalName = this.ActiveDirectory.GetAttributesAsync(new[] { userPrincipalNameAttributeName }, IdentifierKind.SecurityIdentifier, new WindowsPrincipal(WindowsIdentity.GetCurrent())).Result.First().Value;

			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { samAccountNameAttributeName, userPrincipalNameAttributeName }, userPrincipalName, IdentifierKind.UserPrincipalNameWithEmailFallback).Result;
			Assert.AreEqual(2, attributes.Count, "The test must be run on a domain.");
			Assert.AreEqual(samAccountName, attributes.ElementAt(0).Value, "The test must be run on a domain.");
			Assert.AreEqual(userPrincipalName, attributes.ElementAt(1).Value, "The test must be run on a domain.");
		}

		[TestMethod]
		public async Task GetAttributesAsync_WithIdentifierParameter_IfTheIdentifierKindParameterIsWindowsAccountName_And_IfTheNameClaimHasAnInvalidDomainPart_ShouldReturnAnEmptyResult()
		{
			var domain = Guid.NewGuid().ToString();
			var name = $"{domain}\\abc123";

			var result = await this.ActiveDirectory.GetAttributesAsync(Enumerable.Empty<string>(), name, IdentifierKind.WindowsAccountName);

			Assert.IsFalse(result.Any());
		}

		[TestMethod]
		public void GetAttributesAsync_WithIdentifierParameter_IfTheIdentifierKindParameterIsWindowsAccountName_ShouldWorkProperly()
		{
			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { "userPrincipalName" }, WindowsIdentity.GetCurrent().Name, IdentifierKind.WindowsAccountName).Result;

			Assert.AreEqual(1, attributes.Count, "The test must be run on a domain.");
		}

		[TestMethod]
		public void GetAttributesAsync_WithPrincipalParameter_IfTheIdentifierKindParameterIsSamAccountName_ShouldWorkProperly()
		{
			var identityNameParts = WindowsIdentity.GetCurrent().Name.Split('\\', 2);
			string samAccountName = null;
			if(identityNameParts.Length == 2)
				samAccountName = identityNameParts[1];

			var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(JwtClaimTypes.Name, samAccountName) }, "Test"));

			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { "userPrincipalName" }, IdentifierKind.SamAccountName, principal).Result;

			Assert.AreEqual(1, attributes.Count, "The test must be run on a domain.");
		}

		[TestMethod]
		public void GetAttributesAsync_WithPrincipalParameter_IfTheIdentifierKindParameterIsSecurityIdentifier_ShouldWorkProperly()
		{
			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { "userPrincipalName" }, IdentifierKind.SecurityIdentifier, new WindowsPrincipal(WindowsIdentity.GetCurrent())).Result;

			Assert.AreEqual(1, attributes.Count, "The test must be run on a domain.");
		}

		[TestMethod]
		public void GetAttributesAsync_WithPrincipalParameter_IfTheIdentifierKindParameterIsUserPrincipalNameOrEmail_ShouldWorkProperly()
		{
			const string userPrincipalNameAttributeName = "userPrincipalName";
			const string samAccountNameAttributeName = "sAMAccountName";
			var claims = new ClaimsPrincipalBuilder(new WindowsPrincipal(WindowsIdentity.GetCurrent())).ClaimsIdentityBuilders.First().ClaimBuilders;
			var samAccountName = claims.First(claim => string.Equals(ClaimTypes.Name, claim.Type, StringComparison.OrdinalIgnoreCase)).Value.Split('\\').Last();
			var userPrincipalName = this.ActiveDirectory.GetAttributesAsync(new[] { userPrincipalNameAttributeName }, IdentifierKind.SecurityIdentifier, new WindowsPrincipal(WindowsIdentity.GetCurrent())).Result.First().Value;
			claims.Add(ClaimTypes.Upn, userPrincipalName);

			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { samAccountNameAttributeName, userPrincipalNameAttributeName }, IdentifierKind.UserPrincipalNameWithEmailFallback, new ClaimsPrincipal(new ClaimsIdentity(claims.Build()))).Result;
			Assert.AreEqual(2, attributes.Count, "The test must be run on a domain.");
			Assert.AreEqual(samAccountName, attributes.ElementAt(0).Value, "The test must be run on a domain.");
			Assert.AreEqual(userPrincipalName, attributes.ElementAt(1).Value, "The test must be run on a domain.");

			var userPrincipalNameClaim = claims.First(claim => string.Equals(ClaimTypes.Upn, claim.Type, StringComparison.OrdinalIgnoreCase));
			userPrincipalNameClaim.Value = $"{samAccountName}@{IPGlobalProperties.GetIPGlobalProperties().DomainName}";
			claims.Add(ClaimTypes.Email, userPrincipalName);

			attributes = this.ActiveDirectory.GetAttributesAsync(new[] { samAccountNameAttributeName, userPrincipalNameAttributeName }, IdentifierKind.UserPrincipalNameWithEmailFallback, new ClaimsPrincipal(new ClaimsIdentity(claims.Build()))).Result;
			Assert.AreEqual(2, attributes.Count, "The test must be run on a domain.");
			Assert.AreEqual(samAccountName, attributes.ElementAt(0).Value, "The test must be run on a domain.");
			Assert.AreEqual(userPrincipalName, attributes.ElementAt(1).Value, "The test must be run on a domain.");
		}

		[TestMethod]
		public async Task GetAttributesAsync_WithPrincipalParameter_IfTheIdentifierKindParameterIsWindowsAccountName_And_IfTheNameClaimHasAnInvalidDomainPart_ShouldReturnAnEmptyResult()
		{
			var domain = Guid.NewGuid().ToString();
			var name = $"{domain}\\abc123";

			var result = await this.ActiveDirectory.GetAttributesAsync(Enumerable.Empty<string>(), IdentifierKind.WindowsAccountName, new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, name) })));

			Assert.IsFalse(result.Any());
		}

		[TestMethod]
		public void GetAttributesAsync_WithPrincipalParameter_IfTheIdentifierKindParameterIsWindowsAccountName_ShouldWorkProperly()
		{
			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { "userPrincipalName" }, IdentifierKind.WindowsAccountName, new WindowsPrincipal(WindowsIdentity.GetCurrent())).Result;

			Assert.AreEqual(1, attributes.Count, "The test must be run on a domain.");
		}

		protected internal virtual async Task<string> GetSystemDomainFirstPartAsync()
		{
			await Task.CompletedTask;

			return IPGlobalProperties.GetIPGlobalProperties().DomainName.Split('.').First().ToUpperInvariant();
		}

		[TestMethod]
		public void GetSystemDomainName_Test()
		{
			var domainName = this.ActiveDirectory.GetSystemDomainName();
			Assert.IsTrue(domainName.Contains('.', StringComparison.OrdinalIgnoreCase), "The domain-name should be a full domain-name, eg domain.net.");
			Assert.AreEqual(IPGlobalProperties.GetIPGlobalProperties().DomainName, domainName, "The test must be run on a domain (probably on Windows).");
		}

		[TestMethod]
		public async Task GetUserAttributesAsync_WindowsAccountName_Test()
		{
			var windowsAccountName = WindowsIdentity.GetCurrent().Name;
			var windowsAccountNameParts = windowsAccountName.Split('\\', 2);
			string samAccountName = null;
			if(windowsAccountNameParts.Length == 2)
				samAccountName = windowsAccountNameParts[1];

			var result = await this.ActiveDirectory.GetUserAttributesAsync(new[] { "msDS-PrincipalName", "userPrincipalName" }, $"sAMAccountName={samAccountName}");

			Assert.AreEqual(1, result.Count, "The test must be run on a domain.");
			Assert.AreEqual(2, result.ElementAt(0).Value.Count, "The test must be run on a domain.");
			Assert.AreEqual(windowsAccountName, result.ElementAt(0).Value.ElementAt(0).Value);
		}

		[TestMethod]
		public async Task GetUserAttributesAsync_WithSamAccountNameFilter_ShouldWorkProperly()
		{
			var identityNameParts = WindowsIdentity.GetCurrent().Name.Split('\\', 2);
			string samAccountName = null;
			if(identityNameParts.Length == 2)
				samAccountName = identityNameParts[1];

			var result = await this.ActiveDirectory.GetUserAttributesAsync(new[] { "userPrincipalName" }, $"sAMAccountName={samAccountName}");

			Assert.AreEqual(1, result.Count, "The test must be run on a domain.");
			Assert.AreEqual(1, result.ElementAt(0).Value.Count, "The test must be run on a domain.");
		}

		[TestMethod]
		public async Task GetUserAttributesAsync_WithSecurityIdentifierFilter_ShouldWorkProperly()
		{
			var identifier = new WindowsPrincipal(WindowsIdentity.GetCurrent()).FindFirst(ClaimTypes.PrimarySid)?.Value;

			var result = await this.ActiveDirectory.GetUserAttributesAsync(new[] { "userPrincipalName" }, $"objectSid={identifier}");

			Assert.AreEqual(1, result.Count, "The test must be run on a domain.");
			Assert.AreEqual(1, result.ElementAt(0).Value.Count, "The test must be run on a domain.");
		}

		[TestMethod]
		public async Task GetUserAttributesAsync_WithUserPrincipalNameFilter_ShouldWorkProperly()
		{
			const string userPrincipalNameAttributeName = "userPrincipalName";
			const string samAccountNameAttributeName = "sAMAccountName";
			var claims = new ClaimsPrincipalBuilder(new WindowsPrincipal(WindowsIdentity.GetCurrent())).ClaimsIdentityBuilders.First().ClaimBuilders;
			var objectSid = claims.First(claim => string.Equals(ClaimTypes.PrimarySid, claim.Type, StringComparison.OrdinalIgnoreCase)).Value;
			var samAccountName = claims.First(claim => string.Equals(ClaimTypes.Name, claim.Type, StringComparison.OrdinalIgnoreCase)).Value.Split('\\').Last();

			var userPrincipalName = (await this.ActiveDirectory.GetUserAttributesAsync(new[] { userPrincipalNameAttributeName }, $"objectSid={objectSid}")).First().Value.First().Value;

			var result = await this.ActiveDirectory.GetUserAttributesAsync(new[] { samAccountNameAttributeName, userPrincipalNameAttributeName }, $"{userPrincipalNameAttributeName}={userPrincipalName}");
			Assert.AreEqual(1, result.Count);
			var attributes = result.First().Value;
			Assert.AreEqual(2, attributes.Count, "The test must be run on a domain.");
			Assert.AreEqual(samAccountName, attributes.ElementAt(0).Value, "The test must be run on a domain.");
			Assert.AreEqual(userPrincipalName, attributes.ElementAt(1).Value, "The test must be run on a domain.");
		}

		[TestMethod]
		public void LdapConnectionOptions_AuthenticationType_ShouldReturnKerberosByDefult()
		{
			var ldapConnectionOptions = this.ActiveDirectory.LdapConnectionOptions;

			Assert.AreEqual(AuthType.Kerberos, ldapConnectionOptions.AuthenticationType);
		}

		[TestMethod]
		public void LdapConnectionOptions_DirectoryIdentifier_Servers_ShouldIncludeTheSystemDomainNameByDefult()
		{
			var ldapConnectionOptions = this.ActiveDirectory.LdapConnectionOptions;

			Assert.AreEqual(1, ldapConnectionOptions.DirectoryIdentifier.Servers.Count);
			Assert.AreEqual(IPGlobalProperties.GetIPGlobalProperties().DomainName, ldapConnectionOptions.DirectoryIdentifier.Servers.First());
		}

		[TestMethod]
		public async Task Options_WithInvalidRootDistinguishedName_Test()
		{
			await this.OptionsTest("With-Invalid-RootDistinguishedName", "dc=invalid, dc=invalid", false);
		}

		[TestMethod]
		public async Task Options_WithValidRootDistinguishedName_Test()
		{
			var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
			var rootDistinguishedName = string.Join(", ", domain.Split('.').Select(part => $"dc={part}"));

			await this.OptionsTest("With-Valid-RootDistinguishedName", rootDistinguishedName, true, rootDistinguishedName);
		}

		protected internal virtual async Task OptionsTest(string appSettingsIdentifier, string rootDistinguishedName, bool samAccountNameHit, params string[] formatArguments)
		{
			formatArguments ??= Array.Empty<string>();

			await using(var stream = this.GetAppSettingsStream(appSettingsIdentifier, formatArguments))
			{
				var serviceProvider = this.CreateServiceProvider(stream);

				var activeDirectory = (ActiveDirectory)serviceProvider.GetRequiredService<IActiveDirectory>();

				Assert.IsNotNull(activeDirectory);

				Assert.AreEqual(rootDistinguishedName, activeDirectory.RootDistinguishedName);

				var samAccountName = WindowsIdentity.GetCurrent().Name.Split('\\').Last();

				var identifier = samAccountName;
				var attributes = (await activeDirectory.GetAttributesAsync(new[] { "sAMAccountName" }, identifier, IdentifierKind.SamAccountName)).ToArray();
				if(samAccountNameHit)
				{
					Assert.AreEqual(1, attributes.Length);
					Assert.AreEqual("sAMAccountName", attributes.ElementAt(0).Key);
				}
				else
				{
					Assert.IsFalse(attributes.Any());
				}
			}
		}

		#endregion
	}
}