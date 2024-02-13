using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace UnitTests.Security.Claims.Extensions
{
	[TestClass]
	public class ClaimCollectionExtensionTest
	{
		#region Methods

		[TestMethod]
		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		public void FindFirst_IfTheClaimsParameterIsNull_ShouldNotThrowAnExceptions()
		{
			try
			{
				((IEnumerable<Claim>)null).FindFirst();
			}
			catch
			{
				Assert.Fail("Should not throw an exception.");
			}
		}

		#endregion
	}
}