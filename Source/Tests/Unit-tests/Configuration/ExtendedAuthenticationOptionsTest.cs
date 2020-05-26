using System.Linq;
using Microsoft.AspNetCore.Server.IIS;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration;

namespace RegionOrebroLan.Web.Authentication.UnitTests.Configuration
{
	[TestClass]
	public class ExtendedAuthenticationOptionsTest
	{
		#region Methods

		[TestMethod]
		public void Decorators_ShouldContainAWindowsAuthenticationDecoratorByDefault()
		{
			var authenticationOptions = new ExtendedAuthenticationOptions();

			Assert.AreEqual(1, authenticationOptions.Decorators.Count);
			Assert.AreEqual(IISServerDefaults.AuthenticationScheme, authenticationOptions.Decorators.First().Value.AuthenticationSchemes.First().Key);
			Assert.AreEqual(10, authenticationOptions.Decorators.First().Value.AuthenticationSchemes.First().Value);
			Assert.IsTrue(authenticationOptions.Decorators.First().Value.Enabled);
			Assert.AreEqual(typeof(WindowsAuthenticationDecorator).AssemblyQualifiedName, authenticationOptions.Decorators.First().Value.Type);
		}

		[TestMethod]
		public void PostDecorators_ShouldContainACallbackDecoratorByDefault()
		{
			var authenticationOptions = new ExtendedAuthenticationOptions();

			Assert.AreEqual(1, authenticationOptions.PostDecorators.Count);
			Assert.AreEqual("*", authenticationOptions.PostDecorators.First().Value.AuthenticationSchemes.First().Key);
			Assert.AreEqual(10, authenticationOptions.PostDecorators.First().Value.AuthenticationSchemes.First().Value);
			Assert.IsTrue(authenticationOptions.PostDecorators.First().Value.Enabled);
			Assert.AreEqual(typeof(CallbackDecorator).AssemblyQualifiedName, authenticationOptions.PostDecorators.First().Value.Type);
		}

		#endregion
	}
}