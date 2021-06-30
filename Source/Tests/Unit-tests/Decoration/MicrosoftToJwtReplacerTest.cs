using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Web.Authentication.Decoration;

namespace UnitTests.Decoration
{
	[TestClass]
	public class MicrosoftToJwtReplacerTest
	{
		#region Methods

		protected internal virtual async Task<MicrosoftToJwtReplacer> CreateMicrosoftToJwtReplacerAsync(ILoggerFactory loggerFactory = null)
		{
			loggerFactory ??= Mock.Of<ILoggerFactory>();

			return await Task.FromResult(new MicrosoftToJwtReplacer(loggerFactory));
		}

		[TestMethod]
		public async Task Map_Test()
		{
			var microsoftToJwtReplacer = await this.CreateMicrosoftToJwtReplacerAsync();

			Assert.IsTrue(microsoftToJwtReplacer.Replacements.Keys.Any(key => key.StartsWith("http://schemas.microsoft.com/", StringComparison.OrdinalIgnoreCase)));
			Assert.IsFalse(microsoftToJwtReplacer.Replacements.Values.Any(value => value.StartsWith("http://schemas.microsoft.com/", StringComparison.OrdinalIgnoreCase)));
		}

		#endregion
	}
}