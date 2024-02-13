using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Web.Authentication.Decoration.Deprecated;

namespace UnitTests.Decoration.Deprecated
{
	[TestClass]
	public class ReplacerTest
	{
		#region Methods

		protected internal virtual async Task<Replacer> CreateReplacerAsync(ILoggerFactory loggerFactory = null)
		{
			loggerFactory ??= Mock.Of<ILoggerFactory>();

			return await Task.FromResult(new Replacer(loggerFactory));
		}

		[TestMethod]
		public async Task Replacements_ShouldBeEmptyByDefault()
		{
			var replacer = await this.CreateReplacerAsync();
			Assert.AreEqual(0, replacer.Replacements.Count);
		}

		#endregion
	}
}