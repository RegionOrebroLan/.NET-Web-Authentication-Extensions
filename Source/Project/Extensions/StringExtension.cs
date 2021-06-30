using System;
using System.Diagnostics.CodeAnalysis;
using System.Web;

namespace RegionOrebroLan.Web.Authentication.Extensions
{
	public static class StringExtension
	{
		#region Fields

		private const string _colon = ":";

		[SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase")]
		private static readonly string _urlEncodedColon = HttpUtility.UrlEncode(_colon).ToLowerInvariant();

		#endregion

		#region Methods

		[SuppressMessage("Design", "CA1055:URI-like return values should not be strings")]
		public static string UrlDecodeColon(this string value)
		{
			const StringComparison comparison = StringComparison.OrdinalIgnoreCase;

			if(value != null && value.Contains(_urlEncodedColon, comparison))
				value = value.Replace(_urlEncodedColon, _colon, comparison);

			return value;
		}

		[SuppressMessage("Design", "CA1055:URI-like return values should not be strings")]
		public static string UrlEncodeColon(this string value)
		{
			const StringComparison comparison = StringComparison.Ordinal;

			if(value != null && value.Contains(_colon, comparison))
				value = value.Replace(_colon, _urlEncodedColon, comparison);

			return value;
		}

		#endregion
	}
}