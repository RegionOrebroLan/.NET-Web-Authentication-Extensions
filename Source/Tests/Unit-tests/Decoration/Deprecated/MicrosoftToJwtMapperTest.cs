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
	public class MicrosoftToJwtMapperTest
	{
		#region Methods

		protected internal virtual async Task<MicrosoftToJwtMapper> CreateMicrosoftToJwtMapperAsync(ILoggerFactory loggerFactory = null)
		{
			loggerFactory ??= Mock.Of<ILoggerFactory>();

			return await Task.FromResult(new MicrosoftToJwtMapper(loggerFactory));
		}

		[TestMethod]
		public async Task Map_Test()
		{
			var microsoftToJwtMapper = await this.CreateMicrosoftToJwtMapperAsync();

			Assert.IsTrue(microsoftToJwtMapper.Map.Keys.Any(key => key.StartsWith("http://schemas.microsoft.com/", StringComparison.OrdinalIgnoreCase)));
			Assert.IsFalse(microsoftToJwtMapper.Map.Values.Any(value => value.StartsWith("http://schemas.microsoft.com/", StringComparison.OrdinalIgnoreCase)));
		}

		#endregion
	}
}