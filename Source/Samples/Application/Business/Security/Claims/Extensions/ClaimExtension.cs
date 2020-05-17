using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using IdentityModel;

namespace Application.Business.Security.Claims.Extensions
{
	public static class ClaimExtension
	{
		#region Methods

		public static Claim Find(this IEnumerable<Claim> claims, params string[] typeNames)
		{
			claims = (claims ?? Enumerable.Empty<Claim>()).ToArray();

			// ReSharper disable LoopCanBeConvertedToQuery
			foreach(var typeName in typeNames)
			{
				var claim = claims.FirstOrDefault(item => string.Equals(item.Type, typeName, StringComparison.OrdinalIgnoreCase));

				if(claim != null)
					return claim;
			}
			// ReSharper restore LoopCanBeConvertedToQuery

			return null;
		}

		public static Claim FindIdentityProviderClaim(this IEnumerable<Claim> claims)
		{
			return claims.Find(ExtendedClaimTypes.IdentityProvider, JwtClaimTypes.IdentityProvider);
		}

		public static Claim FindNameClaim(this IEnumerable<Claim> claims)
		{
			return claims.Find(ClaimTypes.Name, JwtClaimTypes.Name);
		}

		public static Claim FindUniqueIdentifierClaim(this IEnumerable<Claim> claims)
		{
			return claims.Find(ClaimTypes.NameIdentifier, JwtClaimTypes.Subject);
		}

		#endregion
	}
}