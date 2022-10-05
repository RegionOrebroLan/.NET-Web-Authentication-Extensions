using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using IdentityModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <summary>
	/// Decorator that change the claim-type for the already decorated claims according to the replacements-dictionary property.
	/// The default value of the replacements-dictionary is a Microsoft claim-type to Jwt claim-type map, a corrected JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.
	/// </summary>
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class MicrosoftToJwtReplacementDecorator : ReplacementDecorator
	{
		#region Fields

		private IDictionary<string, string> _correctedDefaultOutboundClaimTypeMap;

		#endregion

		#region Constructors

		public MicrosoftToJwtReplacementDecorator(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		protected internal virtual IDictionary<string, string> CorrectedDefaultOutboundClaimTypeMap
		{
			get
			{
				if(this._correctedDefaultOutboundClaimTypeMap == null)
				{
					var temporaryCorrectedDefaultOutboundClaimTypeMap = new Dictionary<string, string>(JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap, StringComparer.OrdinalIgnoreCase)
					{
						[ClaimTypes.Name] = JwtClaimTypes.Name,
						[ClaimTypes.NameIdentifier] = JwtClaimTypes.Subject
					};

					var correctedDefaultOutboundClaimTypeMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

					foreach(var (key, value) in temporaryCorrectedDefaultOutboundClaimTypeMap)
					{
						correctedDefaultOutboundClaimTypeMap.Add(key.UrlEncodeColon(), value);
					}

					this._correctedDefaultOutboundClaimTypeMap = correctedDefaultOutboundClaimTypeMap;
				}

				return this._correctedDefaultOutboundClaimTypeMap;
			}
		}

		public override IDictionary<string, string> Replacements => this.CorrectedDefaultOutboundClaimTypeMap;

		#endregion
	}
}