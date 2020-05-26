using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using IdentityModel;

namespace RegionOrebroLan.Web.Authentication.Security.Claims.Extensions
{
	public static class ClaimCollectionExtension
	{
		#region Methods

		public static Claim FindFirst(this IEnumerable<Claim> claims, params string[] types)
		{
			claims = (claims ?? Enumerable.Empty<Claim>()).ToArray();

			// ReSharper disable LoopCanBeConvertedToQuery
			foreach(var type in types)
			{
				var claim = claims.FirstOrDefault(item => string.Equals(item.Type, type, StringComparison.OrdinalIgnoreCase));

				if(claim != null)
					return claim;
			}
			// ReSharper restore LoopCanBeConvertedToQuery

			return null;
		}

		public static Claim FindFirstIdentityProviderClaim(this IEnumerable<Claim> claims)
		{
			return claims.FindFirst(GetIdentityProviderClaimTypes());
		}

		public static Claim FindFirstNameClaim(this IEnumerable<Claim> claims)
		{
			return claims.FindFirst(GetNameClaimTypes());
		}

		public static Claim FindFirstUniqueIdentifierClaim(this IEnumerable<Claim> claims)
		{
			return claims.FindFirst(GetUniqueIdentifierClaimTypes());
		}

		public static string[] GetIdentityProviderClaimTypes()
		{
			return new[] {ExtendedClaimTypes.IdentityProvider, JwtClaimTypes.IdentityProvider};
		}

		public static string[] GetNameClaimTypes()
		{
			return new[] {ClaimTypes.Name, JwtClaimTypes.Name};
		}

		public static string[] GetUniqueIdentifierClaimTypes()
		{
			return new[] {ClaimTypes.NameIdentifier, JwtClaimTypes.Subject};
		}

		#endregion
	}
}