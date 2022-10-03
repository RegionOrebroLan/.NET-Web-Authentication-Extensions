using System.Linq;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Web.Authentication.Configuration;

namespace UnitTests.Configuration
{
	[TestClass]
	public class ExtendedAuthenticationOptionsTest
	{
		#region Methods

		[TestMethod]
		public async Task AuthenticationDecorators_ShouldBeEmptyByDefault()
		{
			await Task.CompletedTask;
			Assert.IsFalse(new ExtendedAuthenticationOptions().AuthenticationDecorators.Any());
		}

		[TestMethod]
		public async Task AuthenticationPropertiesDecorators_ShouldBeEmptyByDefault()
		{
			await Task.CompletedTask;
			Assert.IsFalse(new ExtendedAuthenticationOptions().AuthenticationPropertiesDecorators.Any());
		}

		[TestMethod]
		public async Task CallbackDecorators_ShouldBeEmptyByDefault()
		{
			await Task.CompletedTask;
			Assert.IsFalse(new ExtendedAuthenticationOptions().CallbackDecorators.Any());
		}

		#endregion
	}
}