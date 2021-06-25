using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.DirectoryServices;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc />
	public abstract class ActiveDirectoryDecorator : IncludeClaimDecorator
	{
		#region Fields

		private const string _activeDirectoryEmailSource = _activeDirectorySourcePrefix + "Email";
		private const string _activeDirectorySourcePrefix = "ActiveDirectory.";
		private const string _activeDirectoryUserPrincipalNameSource = _activeDirectorySourcePrefix + "UserPrincipalName";
		private IDictionary<string, ClaimMapping> _claimInclusionsMap;

		#endregion

		#region Constructors

		protected ActiveDirectoryDecorator(IActiveDirectory activeDirectory, IOptions<ExtendedAuthenticationOptions> authenticationOptions, ILoggerFactory loggerFactory) : base(loggerFactory)
		{
			this.ActiveDirectory = activeDirectory ?? throw new ArgumentNullException(nameof(activeDirectory));
			this.AuthenticationOptions = authenticationOptions ?? throw new ArgumentNullException(nameof(authenticationOptions));
		}

		#endregion

		#region Properties

		protected internal virtual IActiveDirectory ActiveDirectory { get; }
		public virtual string ActiveDirectoryClaimIssuer { get; set; } = "Active Directory";
		public virtual string ActiveDirectoryEmailAttributeName { get; set; } = "mail";
		protected internal virtual string ActiveDirectoryEmailSource => _activeDirectoryEmailSource;
		public virtual bool ActiveDirectoryIntegration { get; set; } = true;
		protected internal virtual string ActiveDirectorySourcePrefix => _activeDirectorySourcePrefix;
		public virtual string ActiveDirectoryUserPrincipalNameAttributeName { get; set; } = "userPrincipalName";
		protected internal virtual string ActiveDirectoryUserPrincipalNameSource => _activeDirectoryUserPrincipalNameSource;
		protected internal virtual IOptions<ExtendedAuthenticationOptions> AuthenticationOptions { get; }

		public override IDictionary<string, ClaimMapping> ClaimInclusionsMap => this._claimInclusionsMap ??= new Dictionary<string, ClaimMapping>(StringComparer.OrdinalIgnoreCase)
		{
			{
				"Email", new ClaimMapping
				{
					Destination = ClaimTypes.Email,
					Source = this.ActiveDirectoryEmailSource
				}
			},
			{
				"UserPrincipalName", new ClaimMapping
				{
					Destination = ClaimTypes.Upn,
					Source = this.ActiveDirectoryUserPrincipalNameSource
				}
			}
		};

		public virtual IdentifierKind IdentifierKind { get; set; } = IdentifierKind.SecurityIdentifier;

		#endregion

		#region Methods

		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		protected internal override bool TryGetSpecialSourceClaim(ClaimsPrincipal principal, string source, out IClaimBuilder claim)
		{
			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			if(base.TryGetSpecialSourceClaim(principal, source, out claim))
				return true;

			// ReSharper disable InvertIf
			if(!string.IsNullOrWhiteSpace(source) && source.StartsWith(this.ActiveDirectorySourcePrefix, StringComparison.OrdinalIgnoreCase))
			{
				var attributes = new List<string>();

				if(!this.ActiveDirectoryIntegration)
					this.Logger.LogWarningIfEnabled($"Could not get special source-claim for source {source.ToStringRepresentation()}. Active-Directory integration is not enabled.");
				else if(source.Equals(this.ActiveDirectoryEmailSource, StringComparison.OrdinalIgnoreCase))
					attributes.Add(this.ActiveDirectoryEmailAttributeName);
				else if(source.Equals(this.ActiveDirectoryUserPrincipalNameSource, StringComparison.OrdinalIgnoreCase))
					attributes.Add(this.ActiveDirectoryUserPrincipalNameAttributeName);
				else
					this.Logger.LogDebugIfEnabled($"Could not get special source-claim for source {source.ToStringRepresentation()}.");

				if(attributes.Any())
				{
					try
					{
						var result = this.ActiveDirectory.GetAttributesAsync(attributes, this.IdentifierKind, principal).Result;

						if(result.Any())
						{
							claim = new ClaimBuilder
							{
								Type = source,
								Value = result.First().Value
							};

							claim.Issuer = claim.OriginalIssuer = this.ActiveDirectoryClaimIssuer;
						}
						else
						{
							this.Logger.LogWarningIfEnabled($"Could not get special source-claim for source {source.ToStringRepresentation()}. No items were returned for attributes \"{string.Join(", ", attributes)}\".");
						}
					}
					catch(Exception exception)
					{
						this.Logger.LogErrorIfEnabled(exception, $"Could not get special source-claim for source {source.ToStringRepresentation()}.");
					}
				}

				return true;
			}
			// ReSharper restore InvertIf

			return false;
		}

		#endregion
	}
}