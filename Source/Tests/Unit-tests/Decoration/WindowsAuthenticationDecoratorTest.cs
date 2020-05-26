using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration;

namespace RegionOrebroLan.Web.Authentication.UnitTests.Decoration
{
	[TestClass]
	public class WindowsAuthenticationDecoratorTest
	{
		#region Methods

		[TestMethod]
		public void ClaimInclusionsMap_Default_Test()
		{
			var windowsAuthenticationDecorator = this.CreateWindowsAuthenticationDecorator();

			Assert.AreEqual(5, windowsAuthenticationDecorator.ClaimInclusionsMap.Count);
			Assert.AreEqual(ClaimTypes.AuthenticationMethod, windowsAuthenticationDecorator.ClaimInclusionsMap.ElementAt(0).Value.Destination);
			Assert.AreEqual("Principal.Identity.AuthenticationType", windowsAuthenticationDecorator.ClaimInclusionsMap.ElementAt(0).Value.Source);
			Assert.IsNull(windowsAuthenticationDecorator.ClaimInclusionsMap.ElementAt(1).Value.Destination);
			Assert.AreEqual(ClaimTypes.Name, windowsAuthenticationDecorator.ClaimInclusionsMap.ElementAt(1).Value.Source);
			Assert.AreEqual(ClaimTypes.NameIdentifier, windowsAuthenticationDecorator.ClaimInclusionsMap.ElementAt(2).Value.Destination);
			Assert.AreEqual(ClaimTypes.PrimarySid, windowsAuthenticationDecorator.ClaimInclusionsMap.ElementAt(2).Value.Source);
			Assert.IsNull(windowsAuthenticationDecorator.ClaimInclusionsMap.ElementAt(3).Value.Destination);
			Assert.AreEqual(ClaimTypes.PrimarySid, windowsAuthenticationDecorator.ClaimInclusionsMap.ElementAt(3).Value.Source);
			Assert.AreEqual(ClaimTypes.WindowsAccountName, windowsAuthenticationDecorator.ClaimInclusionsMap.ElementAt(4).Value.Destination);
			Assert.AreEqual(ClaimTypes.Name, windowsAuthenticationDecorator.ClaimInclusionsMap.ElementAt(4).Value.Source);
		}

		protected internal virtual WindowsAuthenticationDecorator CreateWindowsAuthenticationDecorator()
		{
			return this.CreateWindowsAuthenticationDecorator(Mock.Of<ILoggerFactory>());
		}

		protected internal virtual WindowsAuthenticationDecorator CreateWindowsAuthenticationDecorator(ILoggerFactory loggerFactory)
		{
			return this.CreateWindowsAuthenticationDecorator(new ExtendedAuthenticationOptions(), loggerFactory);
		}

		protected internal virtual WindowsAuthenticationDecorator CreateWindowsAuthenticationDecorator(ExtendedAuthenticationOptions authenticationOptions, ILoggerFactory loggerFactory)
		{
			return new WindowsAuthenticationDecorator(Options.Create(authenticationOptions), loggerFactory);
		}

		#endregion
	}
}