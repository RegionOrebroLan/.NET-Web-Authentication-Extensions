using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.DirectoryServices.Protocols;
using RegionOrebroLan.DirectoryServices.Protocols.Configuration;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace RegionOrebroLan.Web.Authentication.DirectoryServices
{
	[ServiceConfiguration(ServiceType = typeof(IActiveDirectory))]
	public class ActiveDirectory : IActiveDirectory
	{
		#region Fields

		private ILdapConnectionFactory _ldapConnectionFactory;
		private LdapConnectionOptions _ldapConnectionOptions;
		private string _rootDistinguishedName;
		private string _userContainerDistinguishedName;

		#endregion

		#region Constructors

		public ActiveDirectory(IConfiguration configuration, IParser<LdapConnectionOptions> ldapConnectionOptionsParser, ILoggerFactory loggerFactory, IOptionsMonitor<ExtendedAuthenticationOptions> optionsMonitor)
		{
			this.Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
			this.LdapConnectionOptionsParser = ldapConnectionOptionsParser ?? throw new ArgumentNullException(nameof(ldapConnectionOptionsParser));
			this.Logger = (loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory))).CreateLogger(this.GetType());
			this.OptionsMonitor = optionsMonitor ?? throw new ArgumentNullException(nameof(optionsMonitor));
		}

		#endregion

		#region Properties

		protected internal virtual IConfiguration Configuration { get; }
		protected internal virtual ILdapConnectionFactory LdapConnectionFactory => this._ldapConnectionFactory ??= new LdapConnectionFactory(() => this.LdapConnectionOptions);

		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		protected internal virtual LdapConnectionOptions LdapConnectionOptions
		{
			get
			{
				// ReSharper disable InvertIf
				if(this._ldapConnectionOptions == null)
				{
					string activeDirectoryConnectionStringName = null;
					LdapConnectionOptions ldapConnectionOptions = null;

					try
					{
						activeDirectoryConnectionStringName = this.OptionsMonitor.CurrentValue.ActiveDirectory.ConnectionStringName;

						var activeDirectoryConnectionString = this.Configuration.GetConnectionString(activeDirectoryConnectionStringName);

						if(activeDirectoryConnectionString == null)
							this.Logger.LogInformationIfEnabled($"There is no connection-string named \"{activeDirectoryConnectionStringName}\".");
						else if(string.IsNullOrWhiteSpace(activeDirectoryConnectionString))
							this.Logger.LogInformationIfEnabled($"The connection-string \"{activeDirectoryConnectionStringName}\" is empty or whitespaces only.");

						ldapConnectionOptions = this.LdapConnectionOptionsParser.Parse(activeDirectoryConnectionString);
					}
					catch(Exception exception)
					{
						this.Logger.LogErrorIfEnabled(exception, $"Could not get ldap-connection-options from connection-string \"{activeDirectoryConnectionStringName}\".");
					}

					ldapConnectionOptions ??= new LdapConnectionOptions();
					ldapConnectionOptions.DirectoryIdentifier ??= new DirectoryIdentifierOptions();

					if(!ldapConnectionOptions.DirectoryIdentifier.Servers.Any())
					{
						var domainName = this.GetSystemDomainName();
						this.Logger.LogInformationIfEnabled($"The ldap-connection-options contains no servers. The domain-name \"{domainName}\" is retrieved from the system and added as server.");
						ldapConnectionOptions.DirectoryIdentifier.Servers.Add(domainName);
					}

					if(ldapConnectionOptions.AuthenticationType == null)
					{
						var authenticationType = this.OptionsMonitor.CurrentValue.ActiveDirectory.DefaultAuthenticationType;
						this.Logger.LogInformationIfEnabled($"The authentication-type of the ldap-connection-options is null. Setting it to \"{authenticationType}\".");
						ldapConnectionOptions.AuthenticationType = authenticationType;
					}

					this._ldapConnectionOptions = ldapConnectionOptions;
				}
				// ReSharper restore InvertIf

				return this._ldapConnectionOptions;
			}
		}

		protected internal virtual IParser<LdapConnectionOptions> LdapConnectionOptionsParser { get; }
		protected internal virtual ILogger Logger { get; }
		protected internal virtual IOptionsMonitor<ExtendedAuthenticationOptions> OptionsMonitor { get; }

		protected internal virtual string RootDistinguishedName
		{
			get
			{
				// ReSharper disable InvertIf
				if(this._rootDistinguishedName == null)
				{
					var rootDistinguishedName = this.OptionsMonitor.CurrentValue.ActiveDirectory.RootDistinguishedName;

					if(rootDistinguishedName == null)
					{
						this.Logger.LogInformationIfEnabled("The root-distinguished-name is null.");

						const string defaultNamingContext = "defaultNamingContext";
						const string rootDomainNamingContext = "rootDomainNamingContext";

						using(var connection = this.CreateConnectionAsync().Result)
						{
							var searchResponse = (SearchResponse)connection.SendRequest(new SearchRequest(null, null, SearchScope.Base, defaultNamingContext, rootDomainNamingContext));

							if(searchResponse != null && searchResponse.Entries.Count > 0)
							{
								var entry = searchResponse.Entries[0];
								DirectoryAttribute directoryAttribute = null;

								if(entry.Attributes.Contains(defaultNamingContext))
									directoryAttribute = entry.Attributes[defaultNamingContext];
								else if(entry.Attributes.Contains(rootDomainNamingContext))
									directoryAttribute = entry.Attributes[rootDomainNamingContext];

								if(directoryAttribute != null)
								{
									rootDistinguishedName = this.GetDirectoryAttributeValueAsync(directoryAttribute).Result;
									this.Logger.LogInformationIfEnabled($"Setting the root-distinguished-name to \"{rootDistinguishedName}\".");
								}
							}
						}
					}

					this._rootDistinguishedName = rootDistinguishedName ?? string.Empty;
				}
				// ReSharper restore InvertIf

				return this._rootDistinguishedName;
			}
		}

		protected internal virtual string UserContainerDistinguishedName
		{
			get
			{
				// ReSharper disable InvertIf
				if(this._userContainerDistinguishedName == null)
				{
					var userContainerDistinguishedName = this.OptionsMonitor.CurrentValue.ActiveDirectory.UserContainerDistinguishedName;

					if(userContainerDistinguishedName == null)
					{
						this.Logger.LogInformationIfEnabled("The user-container-distinguished-name is null.");

						userContainerDistinguishedName = this.RootDistinguishedName;

						this.Logger.LogInformationIfEnabled($"Setting the user-container-distinguished-name to \"{userContainerDistinguishedName}\".");
					}

					this._userContainerDistinguishedName = userContainerDistinguishedName ?? string.Empty;
				}
				// ReSharper restore InvertIf

				return this._userContainerDistinguishedName;
			}
		}

		#endregion

		#region Methods

		protected internal virtual async Task<LdapConnection> CreateConnectionAsync()
		{
			var ldapConnection = this.LdapConnectionFactory.Create();

			return await Task.FromResult(ldapConnection).ConfigureAwait(false);
		}

		protected internal virtual async Task<string> CreateDomainControllerLdapFilterAsync(string domain)
		{
			return await Task.FromResult($"(&(objectClass=domain)(objectClass=top)(dc={domain}))").ConfigureAwait(false);
		}

		protected internal virtual async Task<string> CreateLdapFilterAsync(LdapConnection connection, string domain, IdentifierKind identifierKind, ClaimsPrincipal principal)
		{
			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			string ldapFilter;

			switch(identifierKind)
			{
				case IdentifierKind.SamAccountName:
					{
						var nameClaim = principal.Claims.FindFirstNameClaim();

						if(nameClaim == null)
							throw new InvalidOperationException("Could not find a name-claim.");

						var samAccountName = nameClaim.Value;
						ldapFilter = $"sAMAccountName={samAccountName}";

						break;
					}
				case IdentifierKind.SecurityIdentifier:
					{
						var securityIdentifierClaim = principal.Claims.FindFirst(ClaimTypes.PrimarySid, JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[ClaimTypes.PrimarySid]);

						if(securityIdentifierClaim == null)
							throw new InvalidOperationException("Could not find a security-identifier-claim.");

						ldapFilter = $"objectSid={securityIdentifierClaim.Value}";

						break;
					}
				case IdentifierKind.UserPrincipalName:
					{
						var userPrincipalNameClaim = principal.Claims.FindFirst(ClaimTypes.Upn, JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[ClaimTypes.Upn]);

						if(userPrincipalNameClaim == null)
							throw new InvalidOperationException("Could not find a user-principal-name-claim.");

						const string userPrincipalNameAttributeName = "userPrincipalName";

						ldapFilter = $"{userPrincipalNameAttributeName}={userPrincipalNameClaim.Value}";

						var emailClaim = principal.Claims.FindFirst(ClaimTypes.Email, JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[ClaimTypes.Email]);

						if(emailClaim != null)
							ldapFilter = $"|({ldapFilter})({userPrincipalNameAttributeName}={emailClaim.Value})";

						break;
					}
				case IdentifierKind.WindowsAccountName:
					{
						var nameClaim = principal.Claims.FindFirstNameClaim();

						if(nameClaim == null)
							throw new InvalidOperationException("Could not find a name-claim.");

						if(connection == null)
							throw new ArgumentNullException(nameof(connection));

						var windowsAccountNameParts = nameClaim.Value.Split('\\');

						var domainPart = windowsAccountNameParts.FirstOrDefault();

						var domainControllerLdapFilter = await this.CreateDomainControllerLdapFilterAsync(domainPart).ConfigureAwait(false);

						var domainSearchResponse = (SearchResponse)connection.SendRequest(new SearchRequest(this.RootDistinguishedName, domainControllerLdapFilter, SearchScope.Base, "dc"));

						if(domainSearchResponse == null || domainSearchResponse.Entries.Count == 0)
							throw new InvalidOperationException($"The name-claim \"{nameClaim.Value}\" has an invalid domain-part. The domain \"{domainPart}\" is invalid.");

						var samAccountName = windowsAccountNameParts.LastOrDefault();
						ldapFilter = $"sAMAccountName={samAccountName}";

						break;
					}
				default:
					{
						throw new InvalidOperationException($"The identifier-kind {identifierKind} is invalid.");
					}
			}

			return await Task.FromResult($"(&(objectClass=person)(objectClass=user)({ldapFilter}))").ConfigureAwait(false);
		}

		public virtual async Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, string identifier, IdentifierKind identifierKind)
		{
			if(identifier == null)
				throw new ArgumentNullException(nameof(identifier));

			var claimType = await this.GetClaimTypeAsync(identifierKind).ConfigureAwait(false);

			return await this.GetAttributesAsync(attributes, identifierKind, new ClaimsPrincipal(new ClaimsIdentity(new List<Claim> { new(claimType, identifier) }))).ConfigureAwait(false);
		}

		public virtual async Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, IdentifierKind identifierKind, ClaimsPrincipal principal)
		{
			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			try
			{
				return await this.GetAttributesInternalAsync(attributes, identifierKind, principal).ConfigureAwait(false);
			}
			catch(Exception exception)
			{
				throw new InvalidOperationException($"Could not get attributes for principal \"{principal.Identity?.Name}\".", exception);
			}
		}

		protected internal virtual async Task<IDictionary<string, string>> GetAttributesInternalAsync(IEnumerable<string> attributes, IdentifierKind identifierKind, ClaimsPrincipal principal)
		{
			string domain;

			try
			{
				domain = this.LdapConnectionOptions.DirectoryIdentifier.Servers.First();
			}
			catch(Exception exception)
			{
				throw new InvalidProgramException("Could not get domain-name from ldap-connection-options. There is no directory-identifier-server.", exception);
			}

			using(var connection = await this.CreateConnectionAsync().ConfigureAwait(false))
			{
				var ldapFilter = await this.CreateLdapFilterAsync(connection, domain, identifierKind, principal).ConfigureAwait(false);

				return await this.GetAttributesInternalAsync(attributes, connection, ldapFilter, SearchScope.Subtree).ConfigureAwait(false);
			}
		}

		protected internal virtual async Task<IDictionary<string, string>> GetAttributesInternalAsync(IEnumerable<string> attributes, LdapConnection connection, string ldapFilter, SearchScope scope)
		{
			attributes = (attributes ?? Enumerable.Empty<string>()).ToArray();
			var attributesResult = new Dictionary<string, string>();

			var searchResultAttributes = (await this.GetSearchResultEntryAsync(attributes, connection, ldapFilter, scope).ConfigureAwait(false))?.Attributes;

			// ReSharper disable InvertIf
			if(searchResultAttributes != null)
			{
				var searchResultAttributeNames = (searchResultAttributes.AttributeNames?.Cast<string>() ?? Enumerable.Empty<string>()).ToArray();

				foreach(var attribute in attributes)
				{
					if(!searchResultAttributeNames.Contains(attribute, StringComparer.OrdinalIgnoreCase))
						continue;

					var value = await this.GetDirectoryAttributeValueAsync(attribute, searchResultAttributes).ConfigureAwait(false);

					if(value == null)
						continue;

					attributesResult.Add(attribute, value);
				}
			}
			// ReSharper restore InvertIf

			return attributesResult;
		}

		protected internal virtual async Task<string> GetClaimTypeAsync(IdentifierKind identifierKind)
		{
			await Task.CompletedTask.ConfigureAwait(false);

			return identifierKind switch
			{
				IdentifierKind.SecurityIdentifier => ClaimTypes.PrimarySid,
				IdentifierKind.UserPrincipalName => ClaimTypes.Upn,
				IdentifierKind.SamAccountName => ClaimTypes.Name,
				IdentifierKind.WindowsAccountName => ClaimTypes.Name,
				_ => throw new InvalidOperationException($"The identifier-kind {identifierKind} is invalid.")
			};
		}

		protected internal virtual async Task<string> GetDirectoryAttributeValueAsync(DirectoryAttribute directoryAttribute)
		{
			if(directoryAttribute == null)
				throw new ArgumentNullException(nameof(directoryAttribute));

			var values = new List<string>();

			// ReSharper disable All
			for(var i = 0; i < directoryAttribute.Count; i++)
			{
				var value = directoryAttribute[i];

				if(value != null)
					values.Add(value.ToString());
			}
			// ReSharper restore All

			return await Task.FromResult(string.Join(", ", values)).ConfigureAwait(false);
		}

		protected internal virtual async Task<string> GetDirectoryAttributeValueAsync(string attributeName, SearchResultAttributeCollection directoryAttributes)
		{
			if(attributeName == null)
				throw new ArgumentNullException(nameof(attributeName));

			if(directoryAttributes == null)
				throw new ArgumentNullException(nameof(directoryAttributes));

			if(!directoryAttributes.Contains(attributeName))
				return null;

			var directoryAttribute = directoryAttributes[attributeName];

			return await this.GetDirectoryAttributeValueAsync(directoryAttribute).ConfigureAwait(false);
		}

		protected internal virtual async Task<SearchResultEntry> GetSearchResultEntryAsync(IEnumerable<string> attributes, LdapConnection connection, string ldapFilter, SearchScope scope)
		{
			if(connection == null)
				throw new ArgumentNullException(nameof(connection));

			var searchResponse = (SearchResponse)connection.SendRequest(new SearchRequest(this.UserContainerDistinguishedName, ldapFilter, scope, (attributes ?? Enumerable.Empty<string>()).ToArray()));

			return await Task.FromResult(searchResponse?.Entries.Cast<SearchResultEntry>().FirstOrDefault()).ConfigureAwait(false);
		}

		protected internal virtual string GetSystemDomainName()
		{
			return IPGlobalProperties.GetIPGlobalProperties().DomainName;
		}

		#endregion
	}
}