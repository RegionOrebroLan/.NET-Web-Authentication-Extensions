using System.Linq;
using Microsoft.AspNetCore.Server.IIS;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration;

namespace UnitTests.Configuration
{
	[TestClass]
	public class ExtendedAuthenticationOptionsTest
	{
		#region Methods

		[TestMethod]
		public void AuthenticationDecorators_ShouldContainAWindowsAuthenticationDecoratorByDefault()
		{
			var authenticationOptions = new ExtendedAuthenticationOptions();

			Assert.AreEqual(1, authenticationOptions.AuthenticationDecorators.Count);
			Assert.AreEqual(IISServerDefaults.AuthenticationScheme, authenticationOptions.AuthenticationDecorators.First().Value.AuthenticationSchemes.First().Key);
			Assert.AreEqual(10, authenticationOptions.AuthenticationDecorators.First().Value.AuthenticationSchemes.First().Value);
			Assert.IsTrue(authenticationOptions.AuthenticationDecorators.First().Value.Enabled);
			Assert.AreEqual(typeof(WindowsAuthenticationDecorator).AssemblyQualifiedName, authenticationOptions.AuthenticationDecorators.First().Value.Type);
		}

		[TestMethod]
		public void CallbackDecorators_ShouldContainACallbackDecoratorByDefault()
		{
			var authenticationOptions = new ExtendedAuthenticationOptions();

			Assert.AreEqual(1, authenticationOptions.CallbackDecorators.Count);
			Assert.AreEqual("*", authenticationOptions.CallbackDecorators.First().Value.AuthenticationSchemes.First().Key);
			Assert.AreEqual(10, authenticationOptions.CallbackDecorators.First().Value.AuthenticationSchemes.First().Value);
			Assert.IsTrue(authenticationOptions.CallbackDecorators.First().Value.Enabled);
			Assert.AreEqual(typeof(CallbackDecorator).AssemblyQualifiedName, authenticationOptions.CallbackDecorators.First().Value.Type);
		}

		#endregion
	}
}