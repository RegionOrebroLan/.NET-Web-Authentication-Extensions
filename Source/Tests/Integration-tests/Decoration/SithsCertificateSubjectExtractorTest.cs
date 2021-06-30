using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions;

namespace IntegrationTests.Decoration
{
	[TestClass]
	public class SithsCertificateSubjectExtractorTest
	{
		#region Methods

		[TestMethod]
		public async Task AuthenticationDecorator_Test()
		{
			var configuration = Global.CreateConfiguration("appsettings.json", $"Decoration\\Resources\\appsettings.SithsCertificateSubjectExtractor-Decorator.json");
			var services = Global.CreateServices(configuration);
			services.AddAuthentication(Global.CreateCertificateResolver(), configuration, new InstanceFactory());

			await using(var serviceProvider = services.BuildServiceProvider())
			{
				var decorationLoader = serviceProvider.GetRequiredService<IDecorationLoader>();
				var authenticationDecorators = (await decorationLoader.GetAuthenticationDecoratorsAsync("SithsCertificate")).ToArray();
				Assert.AreEqual(1, authenticationDecorators.Length);
				var sithsCertificateSubjectExtractor = (SithsCertificateSubjectExtractor)authenticationDecorators[0];
				Assert.AreEqual(1, sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Count);
				Assert.AreEqual("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/x500distinguishedname", sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.ElementAt(0));
			}
		}

		[TestMethod]
		public async Task CallbackDecorator_Test()
		{
			var configuration = Global.CreateConfiguration("appsettings.json", $"Decoration\\Resources\\appsettings.SithsCertificateSubjectExtractor-Callback-Decorator.json");
			var services = Global.CreateServices(configuration);
			services.AddAuthentication(Global.CreateCertificateResolver(), configuration, new InstanceFactory());

			await using(var serviceProvider = services.BuildServiceProvider())
			{
				var decorationLoader = serviceProvider.GetRequiredService<IDecorationLoader>();
				var callbackDecorators = (await decorationLoader.GetCallbackDecoratorsAsync("SithsCertificate")).ToArray();
				Assert.AreEqual(2, callbackDecorators.Length);
				var sithsCertificateSubjectExtractor = (SithsCertificateSubjectExtractor)callbackDecorators[1];
				Assert.AreEqual(1, sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.Count);
				Assert.AreEqual("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/x500distinguishedname", sithsCertificateSubjectExtractor.CertificateSubjectClaimTypes.ElementAt(0));
			}
		}

		#endregion
	}
}