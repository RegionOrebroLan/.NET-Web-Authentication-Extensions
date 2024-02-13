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
	public class JwtToMicrosoftMapperTest
	{
		#region Methods

		protected internal virtual async Task<JwtToMicrosoftMapper> CreateJwtToMicrosoftMapperAsync(ILoggerFactory loggerFactory = null)
		{
			loggerFactory ??= Mock.Of<ILoggerFactory>();

			return await Task.FromResult(new JwtToMicrosoftMapper(loggerFactory));
		}

		[TestMethod]
		public async Task Map_Test()
		{
			var jwtToMicrosoftMapper = await this.CreateJwtToMicrosoftMapperAsync();

			Assert.IsFalse(jwtToMicrosoftMapper.Map.Keys.Any(key => key.StartsWith("http://schemas.microsoft.com/", StringComparison.OrdinalIgnoreCase)));
			Assert.IsTrue(jwtToMicrosoftMapper.Map.Values.Any(value => value.StartsWith("http://schemas.microsoft.com/", StringComparison.OrdinalIgnoreCase)));
		}

		#endregion
	}
}