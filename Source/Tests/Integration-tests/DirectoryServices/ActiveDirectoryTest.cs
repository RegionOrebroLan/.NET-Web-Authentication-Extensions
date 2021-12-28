using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Claims;
using System.Security.Principal;
using IdentityModel;
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

		protected internal virtual IServiceProvider ConfigureServices()
		{
			var services = Global.CreateServices();

			services.AddAuthentication(Global.CreateCertificateResolver(), Global.Configuration, new InstanceFactory());

			return services.BuildServiceProvider();
		}

		[TestMethod]
		public void GetAttributesAsync_IfTheIdentifierKindParameterIsSamAccountName_ShouldWorkProperly()
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
		public void GetAttributesAsync_IfTheIdentifierKindParameterIsSecurityIdentifier_ShouldWorkProperly()
		{
			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { "userPrincipalName" }, IdentifierKind.SecurityIdentifier, new WindowsPrincipal(WindowsIdentity.GetCurrent())).Result;

			Assert.AreEqual(1, attributes.Count, "The test must be run on a domain.");
		}

		[TestMethod]
		public void GetAttributesAsync_IfTheIdentifierKindParameterIsUserPrincipalName_ShouldWorkProperly()
		{
			const string userPrincipalNameAttributeName = "userPrincipalName";
			const string samAccountNameAttributeName = "sAMAccountName";
			var claims = new ClaimsPrincipalBuilder(new WindowsPrincipal(WindowsIdentity.GetCurrent())).ClaimsIdentityBuilders.First().ClaimBuilders;
			var samAccountName = claims.First(claim => string.Equals(ClaimTypes.Name, claim.Type, StringComparison.OrdinalIgnoreCase)).Value.Split('\\').Last();
			var userPrincipalName = this.ActiveDirectory.GetAttributesAsync(new[] { userPrincipalNameAttributeName }, IdentifierKind.SecurityIdentifier, new WindowsPrincipal(WindowsIdentity.GetCurrent())).Result.First().Value;
			claims.Add(ClaimTypes.Upn, userPrincipalName);

			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { samAccountNameAttributeName, userPrincipalNameAttributeName }, IdentifierKind.UserPrincipalName, new ClaimsPrincipal(new ClaimsIdentity(claims.Build()))).Result;
			Assert.AreEqual(2, attributes.Count, "The test must be run on a domain.");
			Assert.AreEqual(samAccountName, attributes.ElementAt(0).Value, "The test must be run on a domain.");
			Assert.AreEqual(userPrincipalName, attributes.ElementAt(1).Value, "The test must be run on a domain.");

			var userPrincipalNameClaim = claims.First(claim => string.Equals(ClaimTypes.Upn, claim.Type, StringComparison.OrdinalIgnoreCase));
			userPrincipalNameClaim.Value = $"{samAccountName}@{IPGlobalProperties.GetIPGlobalProperties().DomainName}";
			claims.Add(ClaimTypes.Email, userPrincipalName);

			attributes = this.ActiveDirectory.GetAttributesAsync(new[] { samAccountNameAttributeName, userPrincipalNameAttributeName }, IdentifierKind.UserPrincipalName, new ClaimsPrincipal(new ClaimsIdentity(claims.Build()))).Result;
			Assert.AreEqual(2, attributes.Count, "The test must be run on a domain.");
			Assert.AreEqual(samAccountName, attributes.ElementAt(0).Value, "The test must be run on a domain.");
			Assert.AreEqual(userPrincipalName, attributes.ElementAt(1).Value, "The test must be run on a domain.");
		}

		[TestMethod]
		[ExpectedException(typeof(InvalidOperationException))]
		public void GetAttributesAsync_IfTheIdentifierKindParameterIsWindowsAccountName_And_IfTheNameClaimHasAnInvalidDomainPart_ShouldThrowAnInvalidOperationException()
		{
			var domain = Guid.NewGuid().ToString();
			var name = $"{domain}\\abc123";

			try
			{
				_ = this.ActiveDirectory.GetAttributesAsync(Enumerable.Empty<string>(), IdentifierKind.WindowsAccountName, new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, name) }))).Result;
			}
			catch(AggregateException aggregateException)
			{
				if(aggregateException.InnerExceptions.FirstOrDefault() is InvalidOperationException invalidOperationException)
				{
					if(string.Equals($"Could not get attributes for principal \"{name}\".", invalidOperationException.Message, StringComparison.Ordinal))
					{
						if(invalidOperationException.InnerException != null)
						{
							if(string.Equals($"The name-claim \"{name}\" has an invalid domain-part. The domain \"{domain}\" is invalid.", invalidOperationException.InnerException.Message, StringComparison.Ordinal))
								throw invalidOperationException;
						}
					}
				}
			}
		}

		[TestMethod]
		public void GetAttributesAsync_IfTheIdentifierKindParameterIsWindowsAccountName_ShouldWorkProperly()
		{
			var attributes = this.ActiveDirectory.GetAttributesAsync(new[] { "userPrincipalName" }, IdentifierKind.WindowsAccountName, new WindowsPrincipal(WindowsIdentity.GetCurrent())).Result;

			Assert.AreEqual(1, attributes.Count, "The test must be run on a domain.");
		}

		[TestMethod]
		public void GetDomainNameAsync_Test()
		{
			var domainName = this.ActiveDirectory.GetDomainNameAsync().Result;
			Assert.IsTrue(domainName.Contains('.', StringComparison.OrdinalIgnoreCase), "The domain-name should be a full domain-name, eg domain.net.");
			Assert.AreEqual(IPGlobalProperties.GetIPGlobalProperties().DomainName, domainName, "The test must be run on a domain.");
		}

		#endregion
	}
}