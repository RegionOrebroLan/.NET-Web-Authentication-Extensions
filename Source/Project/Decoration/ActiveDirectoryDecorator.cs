using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.DirectoryServices;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.DirectoryServices;
using RegionOrebroLan.Web.Authentication.Extensions;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <summary>
	/// Decorator that can add Active Directory attributes as claims.
	/// </summary>
	/// <inheritdoc cref="Decorator" />
	/// <inheritdoc cref="IAuthenticationDecorator" />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class ActiveDirectoryDecorator : Decorator, IAuthenticationDecorator
	{
		#region Constructors

		public ActiveDirectoryDecorator(IActiveDirectory activeDirectory, IOptionsMonitor<ExtendedAuthenticationOptions> authenticationOptionsMonitor, ILoggerFactory loggerFactory) : base(loggerFactory)
		{
			this.ActiveDirectory = activeDirectory ?? throw new ArgumentNullException(nameof(activeDirectory));
			this.AuthenticationOptionsMonitor = authenticationOptionsMonitor ?? throw new ArgumentNullException(nameof(authenticationOptionsMonitor));
		}

		#endregion

		#region Properties

		protected internal virtual IActiveDirectory ActiveDirectory { get; }
		protected internal virtual IOptionsMonitor<ExtendedAuthenticationOptions> AuthenticationOptionsMonitor { get; }
		public virtual string EmailClaimType { get; set; }

		/// <summary>
		/// The claim-types to get claim-values for the filter-format (FilterFormat) parameters.
		/// </summary>
		public virtual ISet<string> FilterClaimTypes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		/// <summary>
		/// The filter-format to build the custom filter for Active Directory. The values from the filter-claim-types (FilterClaimTypes) will be used as format parameters.
		/// </summary>
		public virtual string FilterFormat { get; set; }

		public virtual IdentifierKind? IdentifierKind { get; set; }

		/// <summary>
		/// Map that maps Active Directory attributes to claims. The key is an Active Directory attribute and the value is a claim-type.
		/// </summary>
		public virtual IDictionary<string, string> Map { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		public virtual string SamAccountNameClaimType { get; set; }
		public virtual string SecurityIdentifierClaimType { get; set; }
		public virtual string UserPrincipalNameClaimType { get; set; }

		#endregion

		#region Methods

		protected internal virtual async Task<string> CreateFilterAsync(IClaimBuilderCollection claims)
		{
			try
			{
				if(this.IdentifierKind != null)
				{
					var identifierKind = this.IdentifierKind.Value;

					this.Logger.LogDebugIfEnabled($"The identifier-kind is set to {identifierKind.ToStringRepresentation()}. Using the identifier-kind {identifierKind.ToStringRepresentation()} for creating the filter.");

					return await this.CreateFilterFromIdentifierKindAsync(claims, identifierKind).ConfigureAwait(false);
				}

				this.Logger.LogDebugIfEnabled($"The identifier-kind is NOT set. Using the filter-format {this.FilterFormat.ToStringRepresentation()} for creating the filter.");

				return await this.CreateFilterFromFilterFormatAsync(claims).ConfigureAwait(false);
			}
			catch(Exception exception)
			{
				throw new InvalidOperationException("Could not create filter.", exception);
			}
		}

		protected internal virtual async Task<string> CreateFilterFromFilterFormatAsync(IClaimBuilderCollection claims)
		{
			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			if(this.FilterFormat == null)
				throw new InvalidOperationException("The filter-format is null.");

			var arguments = claims.Find(this.FilterClaimTypes.ToArray()).Select(claim => claim.Value).ToArray().Cast<object>().ToArray();

			return await Task.FromResult(string.Format(null, this.FilterFormat, arguments)).ConfigureAwait(false);
		}

		protected internal virtual async Task<string> CreateFilterFromIdentifierKindAsync(IClaimBuilderCollection claims, IdentifierKind identifierKind)
		{
			if(claims == null)
				throw new ArgumentNullException(nameof(claims));

			var attributeNames = this.AuthenticationOptionsMonitor.CurrentValue.ActiveDirectory.AttributeNames;
			var filterBuilder = new FilterBuilder { Operator = FilterOperator.Or };

			switch(identifierKind)
			{
				case DirectoryServices.IdentifierKind.Email:
				{
					foreach(var claim in claims.Find(this.EmailClaimType))
					{
						filterBuilder.Filters.Add($"{attributeNames.Email}={claim.Value}");
					}

					if(!filterBuilder.Filters.Any())
						throw new InvalidOperationException($"Could not find any email-claims with claim-type {this.EmailClaimType.ToStringRepresentation()}.");

					break;
				}
				case DirectoryServices.IdentifierKind.SamAccountName:
				{
					foreach(var claim in claims.Find(this.SamAccountNameClaimType))
					{
						filterBuilder.Filters.Add($"{attributeNames.SamAccountName}={claim.Value}");
					}

					if(!filterBuilder.Filters.Any())
						throw new InvalidOperationException($"Could not find any sAMAccountName-claims with claim-type {this.SamAccountNameClaimType.ToStringRepresentation()}.");

					break;
				}
				case DirectoryServices.IdentifierKind.SecurityIdentifier:
				{
					foreach(var claim in claims.Find(this.SecurityIdentifierClaimType))
					{
						filterBuilder.Filters.Add($"{attributeNames.SecurityIdentifier}={claim.Value}");
					}

					if(!filterBuilder.Filters.Any())
						throw new InvalidOperationException($"Could not find any security-identifier-claims with claim-type {this.SecurityIdentifierClaimType.ToStringRepresentation()}.");

					break;
				}
				case DirectoryServices.IdentifierKind.UserPrincipalName:
				{
					foreach(var claim in claims.Find(this.UserPrincipalNameClaimType))
					{
						filterBuilder.Filters.Add($"{attributeNames.UserPrincipalName}={claim.Value}");
					}

					if(!filterBuilder.Filters.Any())
						throw new InvalidOperationException($"Could not find any user-principal-name-claims with claim-type {this.UserPrincipalNameClaimType.ToStringRepresentation()}.");

					break;
				}
				case DirectoryServices.IdentifierKind.UserPrincipalNameWithEmailFallback:
				{
					foreach(var claim in claims.Find(this.UserPrincipalNameClaimType, this.EmailClaimType))
					{
						filterBuilder.Filters.Add($"{attributeNames.UserPrincipalName}={claim.Value}");
					}

					if(!filterBuilder.Filters.Any())
						throw new InvalidOperationException($"Could not find any user-principal-name-claims with claim-type {this.UserPrincipalNameClaimType.ToStringRepresentation()} or email-claims with claim-type {this.EmailClaimType.ToStringRepresentation()}.");

					break;
				}
				default:
				{
					throw new InvalidOperationException($"The identifier-kind {identifierKind.ToStringRepresentation()} is invalid.");
				}
			}

			return await Task.FromResult(filterBuilder.Build()).ConfigureAwait(false);
		}

		public virtual async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			try
			{
				if(claims == null)
					throw new ArgumentNullException(nameof(claims));

				if(this.Map.Any())
				{
					try
					{
						var filter = await this.CreateFilterAsync(claims).ConfigureAwait(false);

						var attributeNames = this.Map.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);

						var result = await this.ActiveDirectory.GetUserAttributesAsync(attributeNames, filter).ConfigureAwait(false);

						var attributes = result.Values.SelectMany(attributes => attributes).ToArray();

						if(attributes.Any())
						{
							var additionalClaims = new ClaimBuilderCollection();

							foreach(var (attributeName, claimType) in this.Map)
							{
								var values = attributes.Where(attribute => string.Equals(attribute.Key, attributeName, StringComparison.OrdinalIgnoreCase)).Select(attribute => attribute.Value).ToArray();

								// ReSharper disable LoopCanBeConvertedToQuery
								foreach(var value in values)
								{
									additionalClaims.Add(new ClaimBuilder { Type = claimType, Value = value });
								}
								// ReSharper restore LoopCanBeConvertedToQuery
							}

							if(additionalClaims.Any())
							{
								var additionalClaimTypes = additionalClaims.Select(claim => claim.Type).ToHashSet(StringComparer.OrdinalIgnoreCase);

								for(var i = claims.Count - 1; i >= 0; i--)
								{
									if(!additionalClaimTypes.Contains(claims[i].Type))
										continue;

									this.Logger.LogDebugIfEnabled($"Removing previous claim {claims[i].Type.ToStringRepresentation()}.");
									claims.RemoveAt(i);
								}

								foreach(var additionalClaim in additionalClaims)
								{
									this.Logger.LogDebugIfEnabled($"Adding additional claim {additionalClaim.Type.ToStringRepresentation()}.");
									claims.Add(additionalClaim);
								}
							}
						}
						else
						{
							this.Logger.LogDebugIfEnabled($"No entries found in Active Directory with filter {filter.ToStringRepresentation()}.");
						}
					}
					catch(Exception exception)
					{
						this.Logger.LogErrorIfEnabled(exception, "Could not add claims from Active Directory user attributes.");
					}
				}
				else
				{
					this.Logger.LogDebugIfEnabled("The map is empty. Skipping Active Directory search.");
				}
			}
			catch(Exception exception)
			{
				var message = $"Could not decorate authentication-scheme {authenticationScheme.ToStringRepresentation()}.";

				this.Logger.LogErrorIfEnabled(exception, message);

				throw new InvalidOperationException(message, exception);
			}
		}

		#endregion
	}
}