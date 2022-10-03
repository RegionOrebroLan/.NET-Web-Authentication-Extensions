using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Decoration.Deprecated
{
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class JwtToMicrosoftReplacer : BasicReplacer
	{
		#region Constructors

		public JwtToMicrosoftReplacer(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		public override IDictionary<string, string> Replacements => JwtSecurityTokenHandler.DefaultInboundClaimTypeMap;

		#endregion
	}
}