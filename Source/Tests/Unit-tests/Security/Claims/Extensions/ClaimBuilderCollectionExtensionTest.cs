using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace RegionOrebroLan.Web.Authentication.UnitTests.Security.Claims.Extensions
{
	[TestClass]
	public class ClaimBuilderCollectionExtensionTest
	{
		#region Methods

		[TestMethod]
		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		public void FindFirst_IfTheClaimsParameterIsNull_ShouldNotThrowAnExceptions()
		{
			try
			{
				((IEnumerable<IClaimBuilder>) null).FindFirst();
			}
			catch
			{
				Assert.Fail("Should not throw an exception.");
			}
		}

		#endregion
	}
}