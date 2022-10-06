using System;
using System.Collections.Generic;
using System.Linq;
using RegionOrebroLan.Security.Claims;

namespace RegionOrebroLan.Web.Authentication.Security.Claims.Extensions
{
	public static class ClaimBuilderCollectionExtension
	{
		#region Methods

		public static IEnumerable<IClaimBuilder> Find(this IEnumerable<IClaimBuilder> claims, params string[] types)
		{
			claims = (claims ?? Enumerable.Empty<IClaimBuilder>()).ToArray();
			var result = new List<IClaimBuilder>();

			foreach(var type in types ?? Array.Empty<string>())
			{
				result.AddRange(claims.Where(claim => string.Equals(claim.Type, type, StringComparison.OrdinalIgnoreCase)));
			}

			return result;
		}

		public static IClaimBuilder FindFirst(this IEnumerable<IClaimBuilder> claims, params string[] types)
		{
			claims = (claims ?? Enumerable.Empty<IClaimBuilder>()).ToArray();

			// ReSharper disable LoopCanBeConvertedToQuery
			foreach(var type in types ?? Array.Empty<string>())
			{
				var claim = claims.FirstOrDefault(item => string.Equals(item.Type, type, StringComparison.OrdinalIgnoreCase));

				if(claim != null)
					return claim;
			}
			// ReSharper restore LoopCanBeConvertedToQuery

			return null;
		}

		public static IClaimBuilder FindFirstIdentityProviderClaim(this IEnumerable<IClaimBuilder> claims)
		{
			return claims.FindFirst(ClaimCollectionExtension.GetIdentityProviderClaimTypes());
		}

		public static IClaimBuilder FindFirstNameClaim(this IEnumerable<IClaimBuilder> claims)
		{
			return claims.FindFirst(ClaimCollectionExtension.GetNameClaimTypes());
		}

		public static IClaimBuilder FindFirstUniqueIdentifierClaim(this IEnumerable<IClaimBuilder> claims)
		{
			return claims.FindFirst(ClaimCollectionExtension.GetUniqueIdentifierClaimTypes());
		}

		#endregion
	}
}