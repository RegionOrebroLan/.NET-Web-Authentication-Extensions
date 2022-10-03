using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Web.Authentication.Decoration.Deprecated;

namespace UnitTests.Decoration.Deprecated
{
	[TestClass]
	public class JwtToMicrosoftReplacerTest
	{
		#region Methods

		protected internal virtual async Task<JwtToMicrosoftReplacer> CreateJwtToMicrosoftReplacerAsync(ILoggerFactory loggerFactory = null)
		{
			loggerFactory ??= Mock.Of<ILoggerFactory>();

			return await Task.FromResult(new JwtToMicrosoftReplacer(loggerFactory));
		}

		[TestMethod]
		public async Task Map_Test()
		{
			var jwtToMicrosoftReplacer = await this.CreateJwtToMicrosoftReplacerAsync();

			Assert.IsFalse(jwtToMicrosoftReplacer.Replacements.Keys.Any(key => key.StartsWith("http://schemas.microsoft.com/", StringComparison.OrdinalIgnoreCase)));
			Assert.IsTrue(jwtToMicrosoftReplacer.Replacements.Values.Any(value => value.StartsWith("http://schemas.microsoft.com/", StringComparison.OrdinalIgnoreCase)));
		}

		#endregion
	}
}