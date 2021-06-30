using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Web.Authentication.Decoration;

namespace UnitTests.Decoration
{
	[TestClass]
	public class MapperTest
	{
		#region Methods

		protected internal virtual async Task<Mapper> CreateMapperAsync(ILoggerFactory loggerFactory = null)
		{
			loggerFactory ??= Mock.Of<ILoggerFactory>();

			return await Task.FromResult(new Mapper(loggerFactory));
		}

		[TestMethod]
		public async Task Map_ShouldBeEmptyByDefault()
		{
			var mapper = await this.CreateMapperAsync();
			Assert.AreEqual(0, mapper.Map.Count);
		}

		#endregion
	}
}