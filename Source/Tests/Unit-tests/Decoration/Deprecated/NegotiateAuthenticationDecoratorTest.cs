using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration.Deprecated;
using RegionOrebroLan.Web.Authentication.DirectoryServices;

namespace UnitTests.Decoration.Deprecated
{
	[TestClass]
	public class NegotiateAuthenticationDecoratorTest
	{
		#region Methods

		[TestMethod]
		public void ClaimInclusionsMap_Default_Test()
		{
			var negotiateAuthenticationDecorator = this.CreateNegotiateAuthenticationDecorator();

			Assert.AreEqual(7, negotiateAuthenticationDecorator.ClaimInclusionsMap.Count);
			Assert.AreEqual(ClaimTypes.AuthenticationMethod, negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(0).Value.Destination);
			Assert.AreEqual("Principal.Identity.AuthenticationType", negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(0).Value.Source);
			Assert.IsNull(negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(1).Value.Destination);
			Assert.AreEqual(ClaimTypes.Name, negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(1).Value.Source);
			Assert.AreEqual(ClaimTypes.NameIdentifier, negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(2).Value.Destination);
			Assert.AreEqual(ClaimTypes.PrimarySid, negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(2).Value.Source);
			Assert.IsNull(negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(3).Value.Destination);
			Assert.AreEqual(ClaimTypes.PrimarySid, negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(3).Value.Source);
			Assert.AreEqual(ClaimTypes.WindowsAccountName, negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(4).Value.Destination);
			Assert.AreEqual(ClaimTypes.Name, negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(4).Value.Source);
			Assert.AreEqual(ClaimTypes.Email, negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(5).Value.Destination);
			Assert.AreEqual("ActiveDirectory.Email", negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(5).Value.Source);
			Assert.AreEqual(ClaimTypes.Upn, negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(6).Value.Destination);
			Assert.AreEqual("ActiveDirectory.UserPrincipalName", negotiateAuthenticationDecorator.ClaimInclusionsMap.ElementAt(6).Value.Source);
		}

		protected internal virtual NegotiateAuthenticationDecorator CreateNegotiateAuthenticationDecorator()
		{
			return this.CreateNegotiateAuthenticationDecorator(Mock.Of<ILoggerFactory>());
		}

		protected internal virtual NegotiateAuthenticationDecorator CreateNegotiateAuthenticationDecorator(ILoggerFactory loggerFactory)
		{
			return this.CreateNegotiateAuthenticationDecorator(new ExtendedAuthenticationOptions(), loggerFactory);
		}

		protected internal virtual NegotiateAuthenticationDecorator CreateNegotiateAuthenticationDecorator(ExtendedAuthenticationOptions authenticationOptions, ILoggerFactory loggerFactory)
		{
			var authenticationOptionsMonitorMock = new Mock<IOptionsMonitor<ExtendedAuthenticationOptions>>();
			authenticationOptionsMonitorMock.Setup(optionsMonitor => optionsMonitor.CurrentValue).Returns(authenticationOptions);
			var authenticationOptionsMonitor = authenticationOptionsMonitorMock.Object;

			return new NegotiateAuthenticationDecorator(Mock.Of<IActiveDirectory>(), authenticationOptionsMonitor, loggerFactory);
		}

		#endregion
	}
}