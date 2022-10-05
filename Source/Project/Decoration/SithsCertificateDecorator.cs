using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using ActiveLogin.Identity.Swedish;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.DirectoryServices;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Extensions;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <summary>
	/// Decorator that sets claims using the subject from the siths-certificate. A siths-certificate subject, that is a distinguished name, contains the following components:
	/// - C = country code
	/// - CN = common name
	/// - E = email
	/// - G = given name
	/// - L = locality
	/// - O = organization
	/// - SERIALNUMBER = hsa-identity or personal identity number
	///	- SN = surname
	/// The serial number can be used as a unique identifier claim, "sub" (subject) / "nameidentifier". It can also be used as a "hda_identity" or "personal_identity_number" claim.
	/// But which one, "hda_identity" or "personal_identity_number", depends on which value the serial number have. To get around this there are two special distinguished component names:
	/// - HSAIDENTITY
	/// - PERSONALIDENTITYNUMBER
	/// So with the following DistinguishedNameComponentToClaimTypeMap:
	/// {
	///		"DistinguishedNameComponentToClaimTypeMap": {
	///			"HSAIDENTITY": "hsa_identity",
	///			"PERSONALIDENTITYNUMBER": "personal_identity_number",
	///			"SERIALNUMBER": "sub"
	///		}
	/// }
	/// you will get a sub-claim and you will also get a hsa_identity or personal_identity_number depending on if the serial number value is a personal identity number or not.
	/// This decorator should be configured as an authentication-decorator.
	/// </summary>
	/// <inheritdoc cref="Decorator" />
	/// <inheritdoc cref="IAuthenticationDecorator" />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class SithsCertificateDecorator : Decorator, IAuthenticationDecorator
	{
		#region Fields

		private IParser<IDistinguishedName> _distinguishedNameParser;

		#endregion

		#region Constructors

		public SithsCertificateDecorator(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		public virtual string DistinguishedNameClaimType { get; set; } = ClaimTypes.X500DistinguishedName;
		public virtual IDictionary<string, string> DistinguishedNameComponentToClaimTypeMap { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		protected internal virtual IParser<IDistinguishedName> DistinguishedNameParser => this._distinguishedNameParser ??= new DistinguishedNameParser(new DistinguishedNameComponentValidator());
		protected internal virtual string HsaIdentityComponentName => "HSAIDENTITY";
		protected internal virtual string PersonalIdentityNumberComponentName => "PERSONALIDENTITYNUMBER";

		/// <summary>
		/// The claim-types to include from de authenticated principal in addition to the claim-types configured in the DistinguishedNameComponentToClaimTypeMap.
		/// </summary>
		public virtual ISet<string> PrincipalClaimTypesToInclude { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		protected internal virtual string SerialNumberComponentName => "SERIALNUMBER";

		#endregion

		#region Methods

		public virtual async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			try
			{
				if(authenticateResult == null)
					throw new ArgumentNullException(nameof(authenticateResult));

				if(claims == null)
					throw new ArgumentNullException(nameof(claims));

				if(this.DistinguishedNameComponentToClaimTypeMap.Any())
				{
					var distinguishedNameClaim = authenticateResult.Principal.Claims.FindFirst(this.DistinguishedNameClaimType);

					if(distinguishedNameClaim != null)
					{
						if(this.DistinguishedNameParser.TryParse(distinguishedNameClaim.Value, out var distinguishedName))
						{
							var distinguishedNameComponentToClaimTypeMap = new Dictionary<string, string>(this.DistinguishedNameComponentToClaimTypeMap, StringComparer.OrdinalIgnoreCase);
							string serialNumber = null;

							if(distinguishedNameComponentToClaimTypeMap.ContainsKey(this.SerialNumberComponentName))
							{
								var serialNumberComponent = distinguishedName.Components.FirstOrDefault(component => string.Equals(component.Name, this.SerialNumberComponentName, StringComparison.OrdinalIgnoreCase));

								if(serialNumberComponent != null)
								{
									serialNumber = serialNumberComponent.Value;

									if(this.SerialNumberIsValid(serialNumber))
									{
										claims.Add(new ClaimBuilder { Type = distinguishedNameComponentToClaimTypeMap[this.SerialNumberComponentName], Value = serialNumber });
									}
									else
									{
										this.Logger.LogWarningIfEnabled($"Skipping the serial-number because the value is {serialNumber.ToStringRepresentation()}.");
									}
								}
								else
								{
									this.Logger.LogWarningIfEnabled($"There is no serial-number component, {this.SerialNumberComponentName.ToStringRepresentation()}, in distinguished name {distinguishedNameClaim.Value}.");
								}

								distinguishedNameComponentToClaimTypeMap.Remove(this.SerialNumberComponentName);
							}

							foreach(var (key, value) in distinguishedNameComponentToClaimTypeMap)
							{
								if(string.Equals(key, this.HsaIdentityComponentName, StringComparison.OrdinalIgnoreCase) || string.Equals(key, this.PersonalIdentityNumberComponentName, StringComparison.OrdinalIgnoreCase))
								{
									if(this.SerialNumberIsValid(serialNumber))
									{
										if(string.Equals(key, this.HsaIdentityComponentName, StringComparison.OrdinalIgnoreCase))
										{
											if(this.IsHsaIdentitySerialNumber(serialNumber))
												claims.Add(new ClaimBuilder { Type = value, Value = serialNumber });
											else
												this.Logger.LogWarningIfEnabled($"Skipping the distinguished name component {key.ToStringRepresentation()} because the serial-number {serialNumber.ToStringRepresentation()} is not a valid hsa-identity.");
										}
										else if(string.Equals(key, this.PersonalIdentityNumberComponentName, StringComparison.OrdinalIgnoreCase))
										{
											if(this.IsPersonalIdentitySerialNumber(serialNumber))
												claims.Add(new ClaimBuilder { Type = value, Value = serialNumber });
											else
												this.Logger.LogWarningIfEnabled($"Skipping the distinguished name component {key.ToStringRepresentation()} because the serial-number {serialNumber.ToStringRepresentation()} is not a valid personal-identity-number.");
										}
									}
									else
									{
										this.Logger.LogWarningIfEnabled($"Skipping the distinguished name component {key.ToStringRepresentation()} because {(serialNumber == null ? "there is no serial-number component" : $"the serial-number component {serialNumber.ToStringRepresentation()} is invalid")} in distinguished name {distinguishedNameClaim.Value}.");
									}
								}
								else
								{
									var component = distinguishedName.Components.FirstOrDefault(component => string.Equals(component.Name, key, StringComparison.OrdinalIgnoreCase));

									if(component != null)
									{
										claims.Add(new ClaimBuilder { Type = value, Value = component.Value });
									}
									else
									{
										this.Logger.LogWarningIfEnabled($"There is no component named {key.ToStringRepresentation()} in distinguished name {distinguishedNameClaim.Value}.");
									}
								}
							}
						}
						else
						{
							this.Logger.LogErrorIfEnabled($"Could not parse the claim-value {distinguishedNameClaim.Value.ToStringRepresentation()}, from claim-type {this.DistinguishedNameClaimType.ToStringRepresentation()}, to a distinguished name.");
						}
					}
					else
					{
						this.Logger.LogWarningIfEnabled($"The principal-claims does not contain the claim-type {this.DistinguishedNameClaimType.ToStringRepresentation()}.");
					}
				}
				else
				{
					this.Logger.LogDebugIfEnabled("The distinguished-name-component-to-claim-type-map is empty.");
				}

				if(this.PrincipalClaimTypesToInclude.Any())
				{
					foreach(var claimType in this.PrincipalClaimTypesToInclude)
					{
						if(claims.FindFirst(claimType) == null)
						{
							var claim = authenticateResult.Principal.Claims.FindFirst(claimType);

							if(claim != null)
								claims.Add(new ClaimBuilder(claim));
							else
								this.Logger.LogDebugIfEnabled($"The principal-claims does not contain the claim-type {claimType.ToStringRepresentation()}.");
						}
						else
						{
							this.Logger.LogDebugIfEnabled($"Skipping add of claim-type {claimType.ToStringRepresentation()} because the claims already contains it.");
						}
					}
				}
				else
				{
					this.Logger.LogDebugIfEnabled("The principal-claim-types-to-include is empty.");
				}
			}
			catch(Exception exception)
			{
				var message = $"Could not decorate authentication-scheme {authenticationScheme.ToStringRepresentation()}.";

				this.Logger.LogErrorIfEnabled(exception, message);

				throw new InvalidOperationException(message, exception);
			}
		}

		protected internal virtual bool IsHsaIdentitySerialNumber(string serialNumber)
		{
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

		protected internal virtual bool IsPersonalIdentitySerialNumber(string serialNumber)
		{
			if(string.IsNullOrWhiteSpace(serialNumber))
				return false;

			// ReSharper disable ConvertIfStatementToReturnStatement

			if(serialNumber.Length != 12)
				return false;

			// ReSharper restore ConvertIfStatementToReturnStatement

			return PersonalIdentityNumber.TryParse(serialNumber, out _);
		}

		protected internal virtual bool SerialNumberIsValid(string serialNumber)
		{
			return !string.IsNullOrWhiteSpace(serialNumber);
		}

		#endregion
	}
}