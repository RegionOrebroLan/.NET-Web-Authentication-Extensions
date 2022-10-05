using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Decoration;
using TestHelpers.Mocks.Logging;

namespace UnitTests.Decoration
{
	[TestClass]
	public class SithsCertificateDecoratorTest : DecoratorTestBase
	{
		#region Fields

		private const string _commonName = "Given-name Family-name";
		private const string _countryCode = "??";
		private const string _distinguishedNameFormat = $"C={_countryCode},CN={_commonName},E={_email},G={_givenName},L={_locality},O={_organization},SERIALNUMBER={{0}},SN={_surname}";
		private const string _email = "given-name.family-name@example.org";
		private const string _givenName = "Given-name";
		private const string _hsaIdentity = "TEST123456789-abcde";
		private const string _locality = "Locality";
		private const string _organization = "Organization";
		private const string _personalIdentityNumber = "189001019802";
		private const string _surname = "Family-name";

		#endregion

		#region Methods

		protected internal virtual async Task<SithsCertificateDecorator> CreateDecoratorAsync(string fileName, ILoggerFactory loggerFactory)
		{
			var decorator = new SithsCertificateDecorator(loggerFactory);

			var configuration = await this.CreateConfigurationAsync(fileName);

			await decorator.InitializeAsync(configuration);

			return await Task.FromResult(decorator);
		}

		protected internal virtual async Task<string> CreateDistinguishedNameAsync(string serialNumber)
		{
			var distinguishedName = string.Format(null, _distinguishedNameFormat, serialNumber);

			return await Task.FromResult(distinguishedName);
		}

		[TestMethod]
		public async Task DecorateAsync_HsaIdentity_Test1()
		{
			var claims = new ClaimBuilderCollection();
			var distinguishedName = await this.CreateDistinguishedNameAsync(_hsaIdentity);

			var principalClaims = new List<Claim>
			{
				new(ClaimTypes.Email, _email),
				new(ClaimTypes.Name, _commonName),
				new(ClaimTypes.Upn, _email),
				new(ClaimTypes.X500DistinguishedName, distinguishedName)
			};

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(null, null, principalClaims));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("Options-1", loggerFactory);

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.AreEqual(7, claims.Count);

				Assert.AreEqual(ClaimTypes.NameIdentifier, claims[0].Type);
				Assert.AreEqual(_hsaIdentity, claims[0].Value);

				Assert.AreEqual(ClaimTypes.GivenName, claims[1].Type);
				Assert.AreEqual(_givenName, claims[1].Value);

				Assert.AreEqual("hsa_identity", claims[2].Type);
				Assert.AreEqual(_hsaIdentity, claims[2].Value);

				Assert.AreEqual(ClaimTypes.Surname, claims[3].Type);
				Assert.AreEqual(_surname, claims[3].Value);

				Assert.AreEqual(ClaimTypes.Email, claims[4].Type);
				Assert.AreEqual(_email, claims[4].Value);

				Assert.AreEqual(ClaimTypes.Name, claims[5].Type);
				Assert.AreEqual(_commonName, claims[5].Value);

				Assert.AreEqual(ClaimTypes.Upn, claims[6].Type);
				Assert.AreEqual(_email, claims[6].Value);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_IfThereAreNoPrincipalClaims_ShouldNotDecorateAnyClaimsAndLog()
		{
			var claims = new ClaimBuilderCollection();

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(null, null, new List<Claim>()));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("Options-1", loggerFactory);

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.IsFalse(claims.Any());

				Assert.AreEqual(4, loggerFactory.Logs.Count());

				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Warning, log.LogLevel);
				Assert.AreEqual("The principal-claims does not contain the claim-type \"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/x500distinguishedname\".", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("The principal-claims does not contain the claim-type \"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress\".", log.Message);

				log = loggerFactory.Logs.ElementAt(2);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("The principal-claims does not contain the claim-type \"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\".", log.Message);

				log = loggerFactory.Logs.ElementAt(3);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("The principal-claims does not contain the claim-type \"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn\".", log.Message);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_IfThereAreNoPrincipalClaimsAndThereIsNoConfiguredDecoration_ShouldNotDecorateAnyClaimsAndLog()
		{
			var claims = new ClaimBuilderCollection();

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(null, null, new List<Claim>()));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = new SithsCertificateDecorator(loggerFactory);

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.IsFalse(claims.Any());

				Assert.AreEqual(2, loggerFactory.Logs.Count());

				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("The distinguished-name-component-to-claim-type-map is empty.", log.Message);

				log = loggerFactory.Logs.ElementAt(1);
				Assert.AreEqual(LogLevel.Debug, log.LogLevel);
				Assert.AreEqual("The principal-claim-types-to-include is empty.", log.Message);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_PersonalIdentityNumber_Test1()
		{
			var claims = new ClaimBuilderCollection();
			var distinguishedName = await this.CreateDistinguishedNameAsync(_personalIdentityNumber);

			var principalClaims = new List<Claim>
			{
				new(ClaimTypes.Email, _email),
				new(ClaimTypes.Name, _commonName),
				new(ClaimTypes.Upn, _email),
				new(ClaimTypes.X500DistinguishedName, distinguishedName)
			};

			var authenticateResult = AuthenticateResult.Success(await this.CreateAuthenticationTicketAsync(null, null, principalClaims));

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("Options-1", loggerFactory);

				await decorator.DecorateAsync(authenticateResult, null, claims, null);

				Assert.AreEqual(7, claims.Count);

				Assert.AreEqual(ClaimTypes.NameIdentifier, claims[0].Type);
				Assert.AreEqual(_personalIdentityNumber, claims[0].Value);

				Assert.AreEqual(ClaimTypes.GivenName, claims[1].Type);
				Assert.AreEqual(_givenName, claims[1].Value);

				Assert.AreEqual("personal_identity_number", claims[2].Type);
				Assert.AreEqual(_personalIdentityNumber, claims[2].Value);

				Assert.AreEqual(ClaimTypes.Surname, claims[3].Type);
				Assert.AreEqual(_surname, claims[3].Value);

				Assert.AreEqual(ClaimTypes.Email, claims[4].Type);
				Assert.AreEqual(_email, claims[4].Value);

				Assert.AreEqual(ClaimTypes.Name, claims[5].Type);
				Assert.AreEqual(_commonName, claims[5].Value);

				Assert.AreEqual(ClaimTypes.Upn, claims[6].Type);
				Assert.AreEqual(_email, claims[6].Value);
			}
		}

		#endregion
	}
}