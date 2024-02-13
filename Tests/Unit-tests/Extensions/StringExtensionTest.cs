using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace UnitTests.Extensions
{
	[TestClass]
	public class StringExtensionTest
	{
		#region Methods

		[TestMethod]
		public async Task UrlDecodeColon_Test()
		{
			await Task.CompletedTask;

			Assert.AreEqual("%3a".UrlDecodeColon(), ":");
			Assert.AreEqual("%3A".UrlDecodeColon(), ":");
			Assert.AreEqual("http%3a//localhost/a/b".UrlDecodeColon(), "http://localhost/a/b");
		}

		[TestMethod]
		public async Task UrlEncodeColon_Test()
		{
			await Task.CompletedTask;

			Assert.AreEqual(":".UrlEncodeColon(), "%3a");
			Assert.AreEqual("http://localhost/a/b".UrlEncodeColon(), "http%3a//localhost/a/b");
		}

		#endregion
	}
}