using System;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Web.Authentication.Decoration;
using TestHelpers.Mocks.Logging;

namespace UnitTests.Decoration
{
	[TestClass]
	public class CertificateAuthenticationDecoratorTest
	{
		#region Fields

		// ReSharper disable PossibleNullReferenceException
		private static readonly string _projectDirectoryPath = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory).Parent.Parent.Parent.FullName;
		// ReSharper restore PossibleNullReferenceException

		#endregion

		#region Properties

		protected internal virtual string ProjectDirectoryPath => _projectDirectoryPath;

		#endregion

		#region Methods

		protected internal virtual CertificateAuthenticationDecorator CreateCertificateAuthenticationDecorator(IHttpContextAccessor httpContextAccessor)
		{
			return this.CreateCertificateAuthenticationDecorator(httpContextAccessor, Mock.Of<ILoggerFactory>());
		}

		protected internal virtual CertificateAuthenticationDecorator CreateCertificateAuthenticationDecorator(IHttpContextAccessor httpContextAccessor, ILoggerFactory loggerFactory)
		{
			return new CertificateAuthenticationDecorator(httpContextAccessor, loggerFactory);
		}

		protected internal virtual X509Certificate2 GetCertificate()
		{
			return new X509Certificate2(Path.Combine(this.ProjectDirectoryPath, @"Decoration\Deprecated\Resources\Certificates", "Unit-test-certificate.cer"));
		}

		[TestMethod]
		public void TryGetSpecialSourceClaim_Email_Test()
		{
			// ReSharper disable ConvertToUsingDeclaration
			using(var certificate = this.GetCertificate())
			{
				using(var loggerFactory = LoggerFactoryMock.Create())
				{
					var httpContextAccessor = new HttpContextAccessor
					{
						HttpContext = new DefaultHttpContext
						{
							Connection = {ClientCertificate = certificate}
						}
					};
					const string source = "Certificate.Email";

					var certificateAuthenticationDecorator = this.CreateCertificateAuthenticationDecorator(httpContextAccessor, loggerFactory);

					Assert.IsTrue(certificateAuthenticationDecorator.TryGetSpecialSourceClaim(new ClaimsPrincipal(), source, out var claim));
					Assert.AreEqual(source, claim.Type);
					Assert.AreEqual("first-name.last-name@company.com", claim.Value);
				}
			}
			// ReSharper restore ConvertToUsingDeclaration
		}

		[TestMethod]
		public void TryGetSpecialSourceClaim_Subject_Test()
		{
			// ReSharper disable ConvertToUsingDeclaration
			using(var certificate = this.GetCertificate())
			{
				using(var loggerFactory = LoggerFactoryMock.Create())
				{
					var httpContextAccessor = new HttpContextAccessor
					{
						HttpContext = new DefaultHttpContext
						{
							Connection = {ClientCertificate = certificate}
						}
					};
					const string source = "Certificate.Subject";

					var certificateAuthenticationDecorator = this.CreateCertificateAuthenticationDecorator(httpContextAccessor, loggerFactory);

					Assert.IsTrue(certificateAuthenticationDecorator.TryGetSpecialSourceClaim(new ClaimsPrincipal(), source, out var claim));
					Assert.AreEqual(source, claim.Type);
					Assert.AreEqual("CN=Unit-test-certificate", claim.Value);
				}
			}
			// ReSharper restore ConvertToUsingDeclaration
		}

		[TestMethod]
		public void TryGetSpecialSourceClaim_Upn_Test()
		{
			// ReSharper disable ConvertToUsingDeclaration
			using(var certificate = this.GetCertificate())
			{
				using(var loggerFactory = LoggerFactoryMock.Create())
				{
					var httpContextAccessor = new HttpContextAccessor
					{
						HttpContext = new DefaultHttpContext
						{
							Connection = {ClientCertificate = certificate}
						}
					};
					const string source = "Certificate.Upn";

					var certificateAuthenticationDecorator = this.CreateCertificateAuthenticationDecorator(httpContextAccessor, loggerFactory);

					Assert.IsTrue(certificateAuthenticationDecorator.TryGetSpecialSourceClaim(new ClaimsPrincipal(), source, out var claim));
					Assert.AreEqual(source, claim.Type);
					Assert.AreEqual("user-name@domain.net", claim.Value);
				}
			}
			// ReSharper restore ConvertToUsingDeclaration
		}

		#endregion
	}
}