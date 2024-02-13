using System.Linq;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Web.Authentication;
using RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions;

namespace IntegrationTests.DependencyInjection.Extensions
{
	[TestClass]
	public class ServiceCollectionExtensionTest
	{
		#region Methods

		[TestMethod]
		public void AddAuthentication_Test()
		{
			var services = Global.CreateServices();

			services.AddAuthentication(Global.CreateCertificateResolver(), Global.Configuration, new InstanceFactory());

			var serviceProvider = services.BuildServiceProvider();

			var authenticationSchemeLoader = serviceProvider.GetRequiredService<IAuthenticationSchemeLoader>();

			Assert.AreEqual(6, authenticationSchemeLoader.ListAsync().Result.Count());

			var authenticationCookieOptions = serviceProvider.GetRequiredService<IOptionsFactory<CookieAuthenticationOptions>>().Create("AuthenticationCookie");
			Assert.AreEqual("/Account/SignIn/", authenticationCookieOptions.LoginPath.Value);
			Assert.AreEqual("/Account/SignOut/", authenticationCookieOptions.LogoutPath.Value);

			var intermediateAuthenticationCookie = serviceProvider.GetRequiredService<IOptionsFactory<CookieAuthenticationOptions>>().Create("IntermediateAuthenticationCookie");
			Assert.AreEqual("/Account/Login", intermediateAuthenticationCookie.LoginPath.Value);
			Assert.AreEqual("/Account/Logout", intermediateAuthenticationCookie.LogoutPath.Value);

			var googleOptions = serviceProvider.GetRequiredService<IOptionsFactory<GoogleOptions>>().Create("Google");
			Assert.AreEqual("260174815090-v4u9lb79btv3pbss9tk9qupvqq0voo7s.apps.googleusercontent.com", googleOptions.ClientId);
			Assert.AreEqual("og6x3CQba47eSpa5XhBJmUui", googleOptions.ClientSecret);
			Assert.AreEqual("AuthenticationCookie", googleOptions.ForwardSignOut);
			Assert.AreEqual("IntermediateAuthenticationCookie", googleOptions.SignInScheme);

			var microsoftAccountOptions = serviceProvider.GetRequiredService<IOptionsFactory<MicrosoftAccountOptions>>().Create("Microsoft");
			Assert.AreEqual("2dadf463-b32c-4602-9866-d5a08b2eb94f", microsoftAccountOptions.ClientId);
			Assert.AreEqual("/O9Y3xO=@4bflHfh@Vd68tlpscYR]ZWL", microsoftAccountOptions.ClientSecret);
			Assert.AreEqual("AuthenticationCookie", microsoftAccountOptions.ForwardSignOut);
			Assert.AreEqual("IntermediateAuthenticationCookie", microsoftAccountOptions.SignInScheme);

			var negotiateOptions = serviceProvider.GetRequiredService<IOptionsFactory<NegotiateOptions>>().Create("Negotiate");
			Assert.AreEqual("Test", negotiateOptions.ClaimsIssuer);
			Assert.AreEqual("Test", negotiateOptions.ForwardDefault);
			Assert.AreEqual("Test", negotiateOptions.ForwardSignOut);
			Assert.IsFalse(negotiateOptions.PersistKerberosCredentials);
			Assert.IsFalse(negotiateOptions.PersistNtlmCredentials);

			var identityServerDemoOptions = serviceProvider.GetRequiredService<IOptionsFactory<OpenIdConnectOptions>>().Create("IdentityServer-Demo");
			Assert.AreEqual("https://demo.identityserver.io/", identityServerDemoOptions.Authority);
			Assert.AreEqual("/signin-idsrv", identityServerDemoOptions.CallbackPath.Value);
			Assert.AreEqual("implicit", identityServerDemoOptions.ClientId);
			Assert.AreEqual("/signout-idsrv", identityServerDemoOptions.RemoteSignOutPath.Value);
			Assert.AreEqual("id_token", identityServerDemoOptions.ResponseType);
			Assert.AreEqual(true, identityServerDemoOptions.SaveTokens);
			Assert.AreEqual("/signout-callback-idsrv", identityServerDemoOptions.SignedOutCallbackPath.Value);
			Assert.AreEqual("name", identityServerDemoOptions.TokenValidationParameters.NameClaimType);
			Assert.AreEqual("role", identityServerDemoOptions.TokenValidationParameters.RoleClaimType);
		}

		#endregion
	}
}