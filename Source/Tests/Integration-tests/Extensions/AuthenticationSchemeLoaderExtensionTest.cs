using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Web.Authentication;
using RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace IntegrationTests.Extensions
{
	[TestClass]
	public class AuthenticationSchemeLoaderExtensionTest
	{
		#region Fields

		private static IAuthenticationSchemeLoader _authenticationSchemeLoader;
		private static IServiceProvider _serviceProvider;

		#endregion

		#region Properties

		protected internal virtual IAuthenticationSchemeLoader AuthenticationSchemeLoader => _authenticationSchemeLoader ??= this.ServiceProvider.GetRequiredService<IAuthenticationSchemeLoader>();

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
		public async Task GetDiagnosticsAsync_ShouldWorkProperly()
		{
			var diagnostics = await this.AuthenticationSchemeLoader.GetDiagnosticsAsync(this.ServiceProvider).ConfigureAwait(false);
			Assert.AreEqual(5, diagnostics.Count);

			Assert.AreEqual("AuthenticationCookie", diagnostics.ElementAt(0).Key.Name);
			Assert.AreEqual(typeof(CookieAuthenticationHandler), diagnostics.ElementAt(0).Key.HandlerType);
			Assert.AreEqual(typeof(CookieAuthenticationOptions), diagnostics.ElementAt(0).Value.GetType());

			Assert.AreEqual("Google", diagnostics.ElementAt(1).Key.Name);
			Assert.AreEqual(typeof(GoogleHandler), diagnostics.ElementAt(1).Key.HandlerType);
			Assert.AreEqual(typeof(GoogleOptions), diagnostics.ElementAt(1).Value.GetType());

			Assert.AreEqual("IdentityServer-Demo", diagnostics.ElementAt(2).Key.Name);
			Assert.AreEqual(typeof(OpenIdConnectHandler), diagnostics.ElementAt(2).Key.HandlerType);
			Assert.AreEqual(typeof(OpenIdConnectOptions), diagnostics.ElementAt(2).Value.GetType());

			Assert.AreEqual("IntermediateAuthenticationCookie", diagnostics.ElementAt(3).Key.Name);
			Assert.AreEqual(typeof(CookieAuthenticationHandler), diagnostics.ElementAt(3).Key.HandlerType);
			Assert.AreEqual(typeof(CookieAuthenticationOptions), diagnostics.ElementAt(3).Value.GetType());

			Assert.AreEqual("Microsoft", diagnostics.ElementAt(4).Key.Name);
			Assert.AreEqual(typeof(MicrosoftAccountHandler), diagnostics.ElementAt(4).Key.HandlerType);
			Assert.AreEqual(typeof(MicrosoftAccountOptions), diagnostics.ElementAt(4).Value.GetType());
		}

		#endregion
	}
}