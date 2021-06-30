using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using ActiveLogin.Identity.Swedish;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.DirectoryServices;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Extensions;
using RegionOrebroLan.Web.Authentication.Security.Claims;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc cref="Decorator" />
	/// <inheritdoc cref="IAuthenticationDecorator" />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class SithsCertificateSubjectExtractor : Decorator, IAuthenticationDecorator
	{
		#region Fields

		private IDictionary<string, string> _componentToClaimMap;
		private IParser<IDistinguishedName> _distinguishedNameParser;

		#endregion

		#region Constructors

		public SithsCertificateSubjectExtractor(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		public virtual ISet<string> CertificateSubjectClaimTypes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		public virtual IDictionary<string, string> ComponentToClaimMap => this._componentToClaimMap ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
		{
			{"CN", JwtClaimTypes.Name},
			{"E", JwtClaimTypes.Email},
			{"G", JwtClaimTypes.GivenName},
			{this.HsaIdentityComponentName, ExtendedClaimTypes.HsaIdentity},
			{this.PersonalIdentityNumberComponentName, ExtendedClaimTypes.PersonalIdentityNumber},
			{this.SerialNumberComponentName, ExtendedClaimTypes.SithsSerialNumber},
			{"SN", JwtClaimTypes.FamilyName}
		};

		protected internal virtual IParser<IDistinguishedName> DistinguishedNameParser => this._distinguishedNameParser ??= new DistinguishedNameParser(new DistinguishedNameComponentValidator());
		protected internal virtual string HsaIdentityComponentName => nameof(ExtendedClaimTypes.HsaIdentity);
		protected internal virtual string PersonalIdentityNumberComponentName => nameof(ExtendedClaimTypes.PersonalIdentityNumber);
		public virtual bool RemoveCertificateSubjectClaimOnSuccess { get; set; } = true;
		public virtual bool ReplaceExistingClaims { get; set; }
		protected internal virtual string SerialNumberComponentName => "SERIALNUMBER";

		#endregion

		#region Methods

		public virtual async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			this.Logger.LogDebugIfEnabled($"DecorateAsync: authentication-scheme = {authenticationScheme.ToStringRepresentation()}, starting...");

			if(authenticateResult == null)
				throw new ArgumentNullException(nameof(authenticateResult));

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			var certificateSubjectClaim = await this.GetCertificateSubjectClaimAsync(claims, authenticateResult.Principal).ConfigureAwait(false);

			if(certificateSubjectClaim == null)
				return;

			var distinguishedName = await this.GetDistinguishedNameAsync(certificateSubjectClaim).ConfigureAwait(false);

			if(distinguishedName == null)
				return;

			var mappedClaims = await this.GetMappedClaimsAsync(distinguishedName).ConfigureAwait(false);

			foreach(var mappedClaim in mappedClaims)
			{
				await this.HandleMappedClaimAsync(claims, mappedClaim).ConfigureAwait(false);
			}

			await this.HandleExistingCertificateSubjectClaims(certificateSubjectClaim, claims).ConfigureAwait(false);
		}

		protected internal virtual async Task<IClaimBuilder> GetCertificateSubjectClaimAsync(IClaimBuilderCollection claims, IPrincipal principal)
		{
			if(!this.CertificateSubjectClaimTypes.Any())
			{
				this.Logger.LogWarningIfEnabled("No certificate-subject-claim-types set.");
				return null;
			}

			var claimTypesValue = string.Join(", ", this.CertificateSubjectClaimTypes.Select(item => item.ToStringRepresentation()));
			var validClaimTypes = this.CertificateSubjectClaimTypes.Where(item => !string.IsNullOrWhiteSpace(item)).ToArray();

			if(!validClaimTypes.Any())
			{
				this.Logger.LogWarningIfEnabled($"No valid certificate-subject-claim-types set: {claimTypesValue}");
				return null;
			}

			claims ??= new ClaimBuilderCollection();
			var claimsPrincipal = principal as ClaimsPrincipal ?? new ClaimsPrincipal(new ClaimsIdentity());

			var claimBuilder = claims.FindFirst(validClaimTypes);

			if(claimBuilder == null)
			{
				var claim = claimsPrincipal.Claims.FindFirst(validClaimTypes);

				if(claim != null)
					claimBuilder = new ClaimBuilder(claim);
			}

			if(claimBuilder == null)
				this.Logger.LogWarningIfEnabled($"Could not find a certificate-subject-claim by searching the following claim-types: {claimTypesValue}");

			return await Task.FromResult(claimBuilder).ConfigureAwait(false);
		}

		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		protected internal virtual async Task<IDistinguishedName> GetDistinguishedNameAsync(IClaimBuilder claim)
		{
			if(claim == null)
				throw new ArgumentNullException(nameof(claim));

			try
			{
				var distinguishedName = this.DistinguishedNameParser.Parse(claim.Value);

				return await Task.FromResult(distinguishedName).ConfigureAwait(false);
			}
			catch(Exception exception)
			{
				this.Logger.LogErrorIfEnabled(exception, $"Could not parse \"{claim.Value}\" to a distinguished-name from claim-type \"{claim.Type}\".");

				return null;
			}
		}

		protected internal virtual async Task<IClaimBuilderCollection> GetMappedClaimsAsync(IDistinguishedName distinguishedName)
		{
			if(distinguishedName == null)
				throw new ArgumentNullException(nameof(distinguishedName));

			var claims = new ClaimBuilderCollection();

			foreach(var component in distinguishedName.Components)
			{
				var name = component?.Name;
				var value = component?.Value;

				if(name == null || !this.ComponentToClaimMap.ContainsKey(name) || string.IsNullOrEmpty(value))
				{
					this.Logger.LogDebugIfEnabled($"Distinguished-name-component {name.ToStringRepresentation()} with value {value.ToStringRepresentation()} will not be mapped.");
					continue;
				}

				var mappedClaimType = this.ComponentToClaimMap[name];

				if(name.Equals(this.SerialNumberComponentName, StringComparison.OrdinalIgnoreCase))
				{
					if(await this.IsHsaIdentitySerialNumberAsync(value).ConfigureAwait(false))
					{
						this.Logger.LogDebugIfEnabled($"The serial-number {value.ToStringRepresentation()} is a hsa-identity.");

						if(this.ComponentToClaimMap.TryGetValue(this.HsaIdentityComponentName, out var hsaIdentityClaimType))
						{
							this.Logger.LogDebugIfEnabled($"Setting mapped claim-type to {hsaIdentityClaimType.ToStringRepresentation()}");
							mappedClaimType = hsaIdentityClaimType;
						}
					}
					else if(await this.IsPersonalIdentitySerialNumberAsync(value).ConfigureAwait(false))
					{
						this.Logger.LogDebugIfEnabled($"The serial-number {value.ToStringRepresentation()} is a personal-identity-number.");

						if(this.ComponentToClaimMap.TryGetValue(this.PersonalIdentityNumberComponentName, out var personalIdentityNumberClaimType))
						{
							this.Logger.LogDebugIfEnabled($"Setting mapped claim-type to {personalIdentityNumberClaimType.ToStringRepresentation()}");
							mappedClaimType = personalIdentityNumberClaimType;
						}
					}
				}

				claims.Add(new ClaimBuilder
				{
					Type = mappedClaimType,
					Value = value
				});
			}

			return await Task.FromResult(claims).ConfigureAwait(false);
		}

		protected internal virtual async Task HandleExistingCertificateSubjectClaims(IClaimBuilder certificateSubjectClaim, IClaimBuilderCollection claims)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			if(certificateSubjectClaim == null)
				throw new ArgumentNullException(nameof(certificateSubjectClaim));

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			if(!this.RemoveCertificateSubjectClaimOnSuccess)
				return;

			foreach(var existingCertificateSubjectClaim in claims.Where(claim => string.Equals(claim.Type, certificateSubjectClaim.Type, StringComparison.OrdinalIgnoreCase)).ToArray())
			{
				this.Logger.LogDebugIfEnabled($"Removing existing certificate-subject-claim with type {existingCertificateSubjectClaim.Type.ToStringRepresentation()} and value {existingCertificateSubjectClaim.Value.ToStringRepresentation()}.");
				claims.Remove(existingCertificateSubjectClaim);
			}
		}

		protected internal virtual async Task HandleMappedClaimAsync(IClaimBuilderCollection claims, IClaimBuilder mappedClaim)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			if(mappedClaim == null)
				throw new ArgumentNullException(nameof(mappedClaim));

			if(string.IsNullOrWhiteSpace(mappedClaim.Type))
			{
				this.Logger.LogDebugIfEnabled($"Ignoring mapped claim with type {mappedClaim.Type.ToStringRepresentation()}.");
				return;
			}

			if(string.IsNullOrEmpty(mappedClaim.Value))
			{
				this.Logger.LogDebugIfEnabled($"Ignoring mapped claim with value {mappedClaim.Value.ToStringRepresentation()}.");
				return;
			}

			var existingClaim = claims.FirstOrDefault(claim => string.Equals(claim.Type, mappedClaim.Type, StringComparison.OrdinalIgnoreCase));

			if(existingClaim == null)
			{
				this.Logger.LogDebugIfEnabled($"Adding mapped claim with type {mappedClaim.Type.ToStringRepresentation()} and value {mappedClaim.Value.ToStringRepresentation()}.");
				claims.Add(mappedClaim);
				return;
			}

			if(this.ReplaceExistingClaims)
			{
				this.Logger.LogDebugIfEnabled($"Replacing existing claim with mapped claim. Replaced claim with type {existingClaim.Type.ToStringRepresentation()} and value {existingClaim.Value.ToStringRepresentation()}. Mapped claim with type {mappedClaim.Type.ToStringRepresentation()} and value {mappedClaim.Value.ToStringRepresentation()}.");
				existingClaim.Issuer = mappedClaim.Issuer;
				existingClaim.OriginalIssuer = mappedClaim.OriginalIssuer;
				existingClaim.Type = mappedClaim.Type;
				existingClaim.Value = mappedClaim.Value;
				existingClaim.ValueType = mappedClaim.ValueType;

				existingClaim.Properties.Clear();

				foreach(var (key, value) in mappedClaim.Properties)
				{
					existingClaim.Properties.Add(key, value);
				}

				return;
			}

			this.Logger.LogDebugIfEnabled($"Skipping mapped claim with type {mappedClaim.Type.ToStringRepresentation()} and value {mappedClaim.Value.ToStringRepresentation()} because a claim with type {existingClaim.Type.ToStringRepresentation()} already exist.");
		}

		protected internal virtual async Task<bool> IsHsaIdentitySerialNumberAsync(string serialNumber)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			if(string.IsNullOrWhiteSpace(serialNumber))
				return false;

			var parts = serialNumber.Split('-');

			if(parts.Length != 2)
				return false;

			if(parts[0].Length < 12)
				return false;

			// ReSharper disable ConvertIfStatementToReturnStatement

			if(parts[1].Length < 1)
				return false;

			// ReSharper restore ConvertIfStatementToReturnStatement

			return true;
		}

		protected internal virtual async Task<bool> IsPersonalIdentitySerialNumberAsync(string serialNumber)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			if(string.IsNullOrWhiteSpace(serialNumber))
				return false;

			// ReSharper disable ConvertIfStatementToReturnStatement

			if(serialNumber.Length != 12)
				return false;

			// ReSharper restore ConvertIfStatementToReturnStatement

			return SwedishPersonalIdentityNumber.TryParse(serialNumber, out var _);
		}

		#endregion
	}
}