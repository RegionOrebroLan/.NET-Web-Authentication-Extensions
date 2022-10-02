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
using RegionOrebroLan.Web.Authentication.Extensions;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace RegionOrebroLan.Web.Authentication.DirectoryServices
{
	/// <inheritdoc />
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

		protected internal virtual async Task<IFilterBuilder> CreateUserFilterBuilderAsync()
		{
			return await Task.FromResult(new FilterBuilder("objectClass=person", "objectClass=user") { Operator = FilterOperator.And }).ConfigureAwait(false);
		}

		[Obsolete("This method will be removed in a later release. Use GetUserAttributesAsync instead.")]
		public virtual async Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, string identifier, IdentifierKind identifierKind)
		{
			if(identifier == null)
				throw new ArgumentNullException(nameof(identifier));

			var claimType = identifierKind switch
			{
				IdentifierKind.Email => ClaimTypes.Email,
				IdentifierKind.SamAccountName => ClaimTypes.Name,
				IdentifierKind.SecurityIdentifier => ClaimTypes.PrimarySid,
				IdentifierKind.UserPrincipalName => ClaimTypes.Upn,
				IdentifierKind.UserPrincipalNameWithEmailFallback => ClaimTypes.Upn,
				IdentifierKind.WindowsAccountName => ClaimTypes.Name,
				_ => throw new InvalidOperationException($"The identifier-kind {identifierKind} is invalid.")
			};

			return await this.GetAttributesAsync(attributes, identifierKind, new ClaimsPrincipal(new ClaimsIdentity(new List<Claim> { new(claimType, identifier) }))).ConfigureAwait(false);
		}

		[Obsolete("This method will be removed in a later release. Use GetUserAttributesAsync instead.")]
		[SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity")]
		public virtual async Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, IdentifierKind identifierKind, ClaimsPrincipal principal)
		{
			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			try
			{
				var attributeNames = this.OptionsMonitor.CurrentValue.ActiveDirectory.AttributeNames;
				var filterBuilder = new FilterBuilder { Operator = FilterOperator.Or };
				var windowsAccountNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

				switch(identifierKind)
				{
					case IdentifierKind.Email:
						{
							foreach(var claim in principal.Claims.Find(ClaimTypes.Email, JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[ClaimTypes.Email]))
							{
								filterBuilder.Filters.Add($"{attributeNames.Email}={claim.Value}");
							}

							if(!filterBuilder.Filters.Any())
								throw new InvalidOperationException("Could not find any email-claims.");

							break;
						}
					case IdentifierKind.SamAccountName:
						{
							foreach(var claim in principal.Claims.Find(ClaimCollectionExtension.GetNameClaimTypes()))
							{
								filterBuilder.Filters.Add($"{attributeNames.SamAccountName}={claim.Value}");
							}

							if(!filterBuilder.Filters.Any())
								throw new InvalidOperationException("Could not find any name-claims.");

							break;
						}
					case IdentifierKind.SecurityIdentifier:
						{
							foreach(var claim in principal.Claims.Find(ClaimTypes.PrimarySid, JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[ClaimTypes.PrimarySid]))
							{
								filterBuilder.Filters.Add($"{attributeNames.SecurityIdentifier}={claim.Value}");
							}

							if(!filterBuilder.Filters.Any())
								throw new InvalidOperationException("Could not find any security-identifier-claims.");

							break;
						}
					case IdentifierKind.UserPrincipalName:
						{
							foreach(var claim in principal.Claims.Find(ClaimTypes.Upn, JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[ClaimTypes.Upn]))
							{
								filterBuilder.Filters.Add($"{attributeNames.UserPrincipalName}={claim.Value}");
							}

							if(!filterBuilder.Filters.Any())
								throw new InvalidOperationException("Could not find any user-principal-name-claims.");

							break;
						}
					case IdentifierKind.UserPrincipalNameWithEmailFallback:
						{
							foreach(var claim in principal.Claims.Find(ClaimTypes.Upn, JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[ClaimTypes.Upn], ClaimTypes.Email, JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[ClaimTypes.Email]))
							{
								filterBuilder.Filters.Add($"{attributeNames.UserPrincipalName}={claim.Value}");
							}

							if(!filterBuilder.Filters.Any())
								throw new InvalidOperationException("Could not find any user-principal-name-claims or email-claims.");

							break;
						}
					case IdentifierKind.WindowsAccountName:
						{
							foreach(var claim in principal.Claims.Find(ClaimCollectionExtension.GetNameClaimTypes()))
							{
								windowsAccountNames.Add(claim.Value);
							}

							if(!windowsAccountNames.Any())
								throw new InvalidOperationException("Could not find any name-claims.");

							// ReSharper disable ForeachCanBePartlyConvertedToQueryUsingAnotherGetEnumerator
							foreach(var windowsAccountName in windowsAccountNames)
							{
								var windowsAccountNameParts = windowsAccountName.Split('\\');

								var samAccountName = windowsAccountNameParts.LastOrDefault();

								filterBuilder.Filters.Add($"{attributeNames.SamAccountName}={samAccountName}");
							}
							// ReSharper restore ForeachCanBePartlyConvertedToQueryUsingAnotherGetEnumerator

							break;
						}
					default:
						{
							throw new InvalidOperationException($"The identifier-kind {identifierKind} is invalid.");
						}
				}

				var attributeList = (attributes ?? Enumerable.Empty<string>()).ToList();

				if(identifierKind == IdentifierKind.WindowsAccountName)
					attributeList.Add(attributeNames.WindowsAccountName);

				var result = await this.GetUserAttributesInternalAsync(attributeList, filterBuilder.Build()).ConfigureAwait(false);
				var resultAttributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

				foreach(var (distinguishedName, items) in result)
				{
					if(identifierKind == IdentifierKind.WindowsAccountName)
					{
						if(!windowsAccountNames.Any())
							continue;

						if(!items.TryGetValue(attributeNames.WindowsAccountName, out var windowsAccountName))
							continue;

						if(!windowsAccountNames.Contains(windowsAccountName))
							continue;

						foreach(var (key, value) in items)
						{
							if(string.Equals(attributeNames.WindowsAccountName, key, StringComparison.OrdinalIgnoreCase))
								continue;

							resultAttributes.Add(key, value);
						}

						break;
					}

					foreach(var (key, value) in items)
					{
						resultAttributes.Add(key, value);
					}

					break;
				}

				return resultAttributes;
			}
			catch(Exception exception)
			{
				throw new InvalidOperationException($"Could not get attributes for principal {principal.Identity?.Name.ToStringRepresentation()}.", exception);
			}
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

		protected internal virtual async Task<IEnumerable<SearchResultEntry>> GetSearchResultAsync(IEnumerable<string> attributes, LdapConnection connection, string filter, SearchScope scope)
		{
			if(connection == null)
				throw new ArgumentNullException(nameof(connection));

			var searchResult = new List<SearchResultEntry>();
			var searchRequest = new SearchRequest(this.UserContainerDistinguishedName, filter, scope, (attributes ?? Enumerable.Empty<string>()).ToArray());
			SearchResponse searchResponse = null;
			var paging = this.OptionsMonitor.CurrentValue.ActiveDirectory.Paging;

			if(paging.Enabled)
			{
				connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
				var pageResultRequestControl = new PageResultRequestControl(paging.PageSize);
				searchRequest.Controls.Add(pageResultRequestControl);

				while(searchResponse == null || pageResultRequestControl.Cookie.Length > 0)
				{
					searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

					// ReSharper disable PossibleNullReferenceException
					var pageResultResponseControl = searchResponse.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
					// ReSharper restore PossibleNullReferenceException

					if(pageResultResponseControl != null)
						pageResultRequestControl.Cookie = pageResultResponseControl.Cookie;

					searchResult.AddRange(searchResponse.Entries.Cast<SearchResultEntry>());
				}
			}
			else
			{
				searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

				// ReSharper disable PossibleNullReferenceException
				searchResult.AddRange(searchResponse.Entries.Cast<SearchResultEntry>());
				// ReSharper restore PossibleNullReferenceException
			}

			return await Task.FromResult(searchResult).ConfigureAwait(false);
		}

		protected internal virtual string GetSystemDomainName()
		{
			return IPGlobalProperties.GetIPGlobalProperties().DomainName;
		}

		public virtual async Task<IDictionary<string, IDictionary<string, string>>> GetUserAttributesAsync(IEnumerable<string> attributes, string filter)
		{
			try
			{
				return await this.GetUserAttributesInternalAsync(attributes, filter).ConfigureAwait(false);
			}
			catch(Exception exception)
			{
				throw new InvalidOperationException($"Could not get user-attributes for filter {filter.ToStringRepresentation()}.", exception);
			}
		}

		protected internal virtual async Task<IDictionary<string, IDictionary<string, string>>> GetUserAttributesInternalAsync(IEnumerable<string> attributes, string filter)
		{
			if(!this.LdapConnectionOptions.DirectoryIdentifier.Servers.Any())
				throw new InvalidOperationException("The ldap-connection-options contains no directory-identifier-server.");

			attributes = (attributes ?? Enumerable.Empty<string>()).ToArray();

			var filterBuilder = await this.CreateUserFilterBuilderAsync().ConfigureAwait(false);
			filterBuilder.Filters.Add(filter);

			var result = new Dictionary<string, IDictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

			using(var connection = await this.CreateConnectionAsync().ConfigureAwait(false))
			{
				foreach(var searchResultEntry in await this.GetSearchResultAsync(attributes, connection, filterBuilder.Build(), SearchScope.Subtree).ConfigureAwait(false))
				{
					var resultAttributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
					var entryAttributes = searchResultEntry.Attributes;

					if(entryAttributes != null)
					{
						var attributeNames = (entryAttributes.AttributeNames?.Cast<string>() ?? Enumerable.Empty<string>()).ToArray();

						foreach(var attribute in attributes)
						{
							if(!attributeNames.Contains(attribute, StringComparer.OrdinalIgnoreCase))
								continue;

							var value = await this.GetDirectoryAttributeValueAsync(attribute, entryAttributes).ConfigureAwait(false);

							if(value == null)
								continue;

							resultAttributes.Add(attribute, value);
						}
					}

					result.Add(searchResultEntry.DistinguishedName, resultAttributes);
				}
			}

			return result;
		}

		#endregion
	}
}