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
	[Obsolete(ObsoleteHelper.Message)]
	public class JwtToMicrosoftMapper : BasicMapper
	{
		#region Constructors

		public JwtToMicrosoftMapper(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		public override IDictionary<string, string> Map => JwtSecurityTokenHandler.DefaultInboundClaimTypeMap;

		#endregion
	}
}