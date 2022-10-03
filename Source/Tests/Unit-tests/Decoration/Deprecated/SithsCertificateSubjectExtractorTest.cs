using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.Security.Claims;
using TestHelpers.Mocks.Logging;

namespace UnitTests.Decoration
{
	[TestClass]
	public class SithsCertificateSubjectExtractorTest
	{
		#region Fields

		private const string _certificateSubjectFormat = "E=given-name.surname@example.org, SERIALNUMBER={0}, G=Given-name, SN=Surname, CN=Given-name Surname, O=Organization, L=County, C=Country-code";

		#endregion

		#region Properties

		protected internal virtual string AuthenticationScheme => "Unit-test-authentication-scheme";
		protected internal virtual string AuthenticationType => "Unit-test";
		protected internal virtual string HsaIdentityCertificateSubject => string.Format(null, _certificateSubjectFormat, "AB0123456789-abc123");
		protected internal virtual string InvalidHsaIdentityCertificateSubject => string.Format(null, _certificateSubjectFormat, "0123456789-abc123");
		protected internal virtual string InvalidPersonalIdentityNumberCertificateSubject => string.Format(null, _certificateSubjectFormat, "189002149807");
		protected internal virtual string PersonalIdentityNumberCertificateSubject => string.Format(null, _certificateSubjectFormat, "189002149806");

		#endregion

		#region Methods

		[TestMethod]
		public async Task CertificateSubjectClaimTypes_ShouldReturnAnEmptySetByDefault()
		{
			var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync();
			Assert.IsNotNull(sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes);
			Assert.IsFalse(sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Any());
		}

		protected internal virtual async Task<AuthenticateResult> CreateAuthenticateResultAsync(params IClaimBuilder[] claims)
		{
			var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims.Select(claim => claim.Build()), this.AuthenticationType));
			var authenticationTicket = new AuthenticationTicket(claimsPrincipal, this.AuthenticationScheme);

			return await Task.FromResult(AuthenticateResult.Success(authenticationTicket));
		}

		protected internal virtual async Task<SithsCertificateSubjectExtractor> CreateSithsCertificateSubjectExtractorAsync(ILoggerFactory loggerFactory = null)
		{
			loggerFactory ??= Mock.Of<ILoggerFactory>();

			return await Task.FromResult(new SithsCertificateSubjectExtractor(loggerFactory));
		}

		[TestMethod]
		public async Task DecorateAsync_HsaIdentity_FromClaims_Test()
		{
			const string certificateSubjectClaimType = "Test";
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder
				{
					Type = certificateSubjectClaimType,
					Value = this.HsaIdentityCertificateSubject
				}
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(null);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(string.Empty);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add("   ");
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(certificateSubjectClaimType);
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(5, claims.Count);
				Assert.AreEqual(JwtClaimTypes.Email, claims.ElementAt(0).Type);
				Assert.AreEqual("given-name.surname@example.org", claims.ElementAt(0).Value);
				Assert.AreEqual(ExtendedClaimTypes.HsaIdentity, claims.ElementAt(1).Type);
				Assert.AreEqual("AB0123456789-abc123", claims.ElementAt(1).Value);
				Assert.AreEqual(JwtClaimTypes.GivenName, claims.ElementAt(2).Type);
				Assert.AreEqual("Given-name", claims.ElementAt(2).Value);
				Assert.AreEqual(JwtClaimTypes.FamilyName, claims.ElementAt(3).Type);
				Assert.AreEqual("Surname", claims.ElementAt(3).Value);
				Assert.AreEqual(JwtClaimTypes.Name, claims.ElementAt(4).Type);
				Assert.AreEqual("Given-name Surname", claims.ElementAt(4).Value);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_HsaIdentity_FromPrincipal_Test()
		{
			const string certificateSubjectClaimType = "Test";
			var claims = new ClaimBuilderCollection();

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(null);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(string.Empty);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add("   ");
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(certificateSubjectClaimType);
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(new ClaimBuilder {Type = certificateSubjectClaimType, Value = this.HsaIdentityCertificateSubject}), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(5, claims.Count);
				Assert.AreEqual(JwtClaimTypes.Email, claims.ElementAt(0).Type);
				Assert.AreEqual("given-name.surname@example.org", claims.ElementAt(0).Value);
				Assert.AreEqual(ExtendedClaimTypes.HsaIdentity, claims.ElementAt(1).Type);
				Assert.AreEqual("AB0123456789-abc123", claims.ElementAt(1).Value);
				Assert.AreEqual(JwtClaimTypes.GivenName, claims.ElementAt(2).Type);
				Assert.AreEqual("Given-name", claims.ElementAt(2).Value);
				Assert.AreEqual(JwtClaimTypes.FamilyName, claims.ElementAt(3).Type);
				Assert.AreEqual("Surname", claims.ElementAt(3).Value);
				Assert.AreEqual(JwtClaimTypes.Name, claims.ElementAt(4).Type);
				Assert.AreEqual("Given-name Surname", claims.ElementAt(4).Value);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_IfCertificateSubjectClaimTypesIsEmpty_ShouldLogWarning()
		{
			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				Assert.IsFalse(sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Any());
				Assert.IsFalse(loggerFactory.Logs.Any());
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, new ClaimBuilderCollection(), null);
				var warningLogs = loggerFactory.Logs.Where(log => log.LogLevel == LogLevel.Warning).ToArray();
				Assert.AreEqual(1, warningLogs.Length);
				Assert.AreEqual("No certificate-subject-claim-types set.", warningLogs.First().Message);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_IfCertificateSubjectClaimTypesOnlyContainsInvalidValues_ShouldLogWarning()
		{
			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(null);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(string.Empty);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add("   ");
				Assert.IsFalse(loggerFactory.Logs.Any());
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, new ClaimBuilderCollection(), null);
				var warningLogs = loggerFactory.Logs.Where(log => log.LogLevel == LogLevel.Warning).ToArray();
				Assert.AreEqual(1, warningLogs.Length);
				Assert.AreEqual("No valid certificate-subject-claim-types set: null, \"\", \"   \"", warningLogs.First().Message);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_IfNoCertificateSubjectClaimIsFound_ShouldLogWarning()
		{
			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(null);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(string.Empty);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add("   ");
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add("Test");
				Assert.IsFalse(loggerFactory.Logs.Any());
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, new ClaimBuilderCollection(), null);
				var warningLogs = loggerFactory.Logs.Where(log => log.LogLevel == LogLevel.Warning).ToArray();
				Assert.AreEqual(1, warningLogs.Length);
				Assert.AreEqual("Could not find a certificate-subject-claim by searching the following claim-types: null, \"\", \"   \", \"Test\"", warningLogs.First().Message);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_InvalidHsaIdentity_FromClaims_Test()
		{
			const string certificateSubjectClaimType = "Test";
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder
				{
					Type = certificateSubjectClaimType,
					Value = this.InvalidHsaIdentityCertificateSubject
				}
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(null);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(string.Empty);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add("   ");
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(certificateSubjectClaimType);
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(5, claims.Count);
				Assert.AreEqual(JwtClaimTypes.Email, claims.ElementAt(0).Type);
				Assert.AreEqual("given-name.surname@example.org", claims.ElementAt(0).Value);
				Assert.AreEqual(ExtendedClaimTypes.SithsSerialNumber, claims.ElementAt(1).Type);
				Assert.AreEqual("0123456789-abc123", claims.ElementAt(1).Value);
				Assert.AreEqual(JwtClaimTypes.GivenName, claims.ElementAt(2).Type);
				Assert.AreEqual("Given-name", claims.ElementAt(2).Value);
				Assert.AreEqual(JwtClaimTypes.FamilyName, claims.ElementAt(3).Type);
				Assert.AreEqual("Surname", claims.ElementAt(3).Value);
				Assert.AreEqual(JwtClaimTypes.Name, claims.ElementAt(4).Type);
				Assert.AreEqual("Given-name Surname", claims.ElementAt(4).Value);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_InvalidHsaIdentity_FromPrincipal_Test()
		{
			const string certificateSubjectClaimType = "Test";
			var claims = new ClaimBuilderCollection();

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add("   ");
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(certificateSubjectClaimType);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(string.Empty);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(null);
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(new ClaimBuilder {Type = certificateSubjectClaimType, Value = this.InvalidHsaIdentityCertificateSubject}), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(5, claims.Count);
				Assert.AreEqual(JwtClaimTypes.Email, claims.ElementAt(0).Type);
				Assert.AreEqual("given-name.surname@example.org", claims.ElementAt(0).Value);
				Assert.AreEqual(ExtendedClaimTypes.SithsSerialNumber, claims.ElementAt(1).Type);
				Assert.AreEqual("0123456789-abc123", claims.ElementAt(1).Value);
				Assert.AreEqual(JwtClaimTypes.GivenName, claims.ElementAt(2).Type);
				Assert.AreEqual("Given-name", claims.ElementAt(2).Value);
				Assert.AreEqual(JwtClaimTypes.FamilyName, claims.ElementAt(3).Type);
				Assert.AreEqual("Surname", claims.ElementAt(3).Value);
				Assert.AreEqual(JwtClaimTypes.Name, claims.ElementAt(4).Type);
				Assert.AreEqual("Given-name Surname", claims.ElementAt(4).Value);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_InvalidPersonalIdentityNumber_FromClaims_Test()
		{
			const string certificateSubjectClaimType = "Test";
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder
				{
					Type = certificateSubjectClaimType,
					Value = this.InvalidPersonalIdentityNumberCertificateSubject
				}
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(certificateSubjectClaimType);
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(5, claims.Count);
				Assert.AreEqual(JwtClaimTypes.Email, claims.ElementAt(0).Type);
				Assert.AreEqual("given-name.surname@example.org", claims.ElementAt(0).Value);
				Assert.AreEqual(ExtendedClaimTypes.SithsSerialNumber, claims.ElementAt(1).Type);
				Assert.AreEqual("189002149807", claims.ElementAt(1).Value);
				Assert.AreEqual(JwtClaimTypes.GivenName, claims.ElementAt(2).Type);
				Assert.AreEqual("Given-name", claims.ElementAt(2).Value);
				Assert.AreEqual(JwtClaimTypes.FamilyName, claims.ElementAt(3).Type);
				Assert.AreEqual("Surname", claims.ElementAt(3).Value);
				Assert.AreEqual(JwtClaimTypes.Name, claims.ElementAt(4).Type);
				Assert.AreEqual("Given-name Surname", claims.ElementAt(4).Value);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_InvalidPersonalIdentityNumber_FromPrincipal_Test()
		{
			const string certificateSubjectClaimType = "Test";
			var claims = new ClaimBuilderCollection();

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(certificateSubjectClaimType);
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(new ClaimBuilder {Type = certificateSubjectClaimType, Value = this.InvalidPersonalIdentityNumberCertificateSubject}), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(5, claims.Count);
				Assert.AreEqual(JwtClaimTypes.Email, claims.ElementAt(0).Type);
				Assert.AreEqual("given-name.surname@example.org", claims.ElementAt(0).Value);
				Assert.AreEqual(ExtendedClaimTypes.SithsSerialNumber, claims.ElementAt(1).Type);
				Assert.AreEqual("189002149807", claims.ElementAt(1).Value);
				Assert.AreEqual(JwtClaimTypes.GivenName, claims.ElementAt(2).Type);
				Assert.AreEqual("Given-name", claims.ElementAt(2).Value);
				Assert.AreEqual(JwtClaimTypes.FamilyName, claims.ElementAt(3).Type);
				Assert.AreEqual("Surname", claims.ElementAt(3).Value);
				Assert.AreEqual(JwtClaimTypes.Name, claims.ElementAt(4).Type);
				Assert.AreEqual("Given-name Surname", claims.ElementAt(4).Value);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_PersonalIdentityNumber_FromClaims_Test()
		{
			const string certificateSubjectClaimType = "Test";
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder
				{
					Type = certificateSubjectClaimType,
					Value = this.PersonalIdentityNumberCertificateSubject
				}
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(certificateSubjectClaimType);
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(5, claims.Count);
				Assert.AreEqual(JwtClaimTypes.Email, claims.ElementAt(0).Type);
				Assert.AreEqual("given-name.surname@example.org", claims.ElementAt(0).Value);
				Assert.AreEqual(ExtendedClaimTypes.PersonalIdentityNumber, claims.ElementAt(1).Type);
				Assert.AreEqual("189002149806", claims.ElementAt(1).Value);
				Assert.AreEqual(JwtClaimTypes.GivenName, claims.ElementAt(2).Type);
				Assert.AreEqual("Given-name", claims.ElementAt(2).Value);
				Assert.AreEqual(JwtClaimTypes.FamilyName, claims.ElementAt(3).Type);
				Assert.AreEqual("Surname", claims.ElementAt(3).Value);
				Assert.AreEqual(JwtClaimTypes.Name, claims.ElementAt(4).Type);
				Assert.AreEqual("Given-name Surname", claims.ElementAt(4).Value);
			}
		}

		[TestMethod]
		public async Task DecorateAsync_PersonalIdentityNumber_FromPrincipal_Test()
		{
			const string certificateSubjectClaimType = "Test";
			var claims = new ClaimBuilderCollection();

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync(loggerFactory);
				sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Add(certificateSubjectClaimType);
				await sithsCertificateSubjectExtractor.DecorateAsync(await this.CreateAuthenticateResultAsync(new ClaimBuilder {Type = certificateSubjectClaimType, Value = this.PersonalIdentityNumberCertificateSubject}), this.AuthenticationScheme, claims, null);
				Assert.AreEqual(5, claims.Count);
				Assert.AreEqual(JwtClaimTypes.Email, claims.ElementAt(0).Type);
				Assert.AreEqual("given-name.surname@example.org", claims.ElementAt(0).Value);
				Assert.AreEqual(ExtendedClaimTypes.PersonalIdentityNumber, claims.ElementAt(1).Type);
				Assert.AreEqual("189002149806", claims.ElementAt(1).Value);
				Assert.AreEqual(JwtClaimTypes.GivenName, claims.ElementAt(2).Type);
				Assert.AreEqual("Given-name", claims.ElementAt(2).Value);
				Assert.AreEqual(JwtClaimTypes.FamilyName, claims.ElementAt(3).Type);
				Assert.AreEqual("Surname", claims.ElementAt(3).Value);
				Assert.AreEqual(JwtClaimTypes.Name, claims.ElementAt(4).Type);
				Assert.AreEqual("Given-name Surname", claims.ElementAt(4).Value);
			}
		}

		[TestMethod]
		public async Task RemoveCertificateSubjectClaimOnSuccess_ShouldReturnTrueByDefault()
		{
			var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync();
			Assert.IsTrue(sithsCertificateSubjectExtractor.RemoveCertificateSubjectClaimOnSuccess);
		}

		[TestMethod]
		public async Task ReplaceExistingClaims_ShouldReturnFalseByDefault()
		{
			var sithsCertificateSubjectExtractor = await this.CreateSithsCertificateSubjectExtractorAsync();
			Assert.IsFalse(sithsCertificateSubjectExtractor.ReplaceExistingClaims);
		}

		#endregion
	}
}