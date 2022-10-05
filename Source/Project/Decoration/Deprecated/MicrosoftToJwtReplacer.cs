using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Decoration.Deprecated
{
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	[Obsolete("This decorator is deprecated. Use RegionOrebroLan.Web.Authentication.Decoration.MicrosoftToJwtReplacementDecorator instead.")]
	public class MicrosoftToJwtReplacer : BasicReplacer
	{
		#region Constructors

		public MicrosoftToJwtReplacer(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		public override IDictionary<string, string> Replacements => JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap;

		#endregion
	}
}