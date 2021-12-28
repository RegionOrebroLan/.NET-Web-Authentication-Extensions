using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Security.Claims.Extensions;

namespace RegionOrebroLan.Web.Authentication.DirectoryServices
{
	[ServiceConfiguration(ServiceType = typeof(IActiveDirectory))]
	public class ActiveDirectory : IActiveDirectory
	{
		#region Constructors

		public ActiveDirectory(IOptions<ExtendedAuthenticationOptions> options)
		{
			this.Options = options ?? throw new ArgumentNullException(nameof(options));
		}

		#endregion

		#region Properties

		protected internal virtual IOptions<ExtendedAuthenticationOptions> Options { get; }

		#endregion

		#region Methods

		protected internal virtual async Task<LdapConnection> CreateConnectionAsync(string domainName)
		{
			var port = this.Options.Value.ActiveDirectory.Port;
			var server = domainName + (port != null ? $":{port}" : null);

			var connection = new LdapConnection(server)
			{
				AuthType = this.Options.Value.ActiveDirectory.AuthenticationType,
				SessionOptions = { ProtocolVersion = 3 }
			};

			return await Task.FromResult(connection).ConfigureAwait(false);
		}

		protected internal virtual async Task<string> CreateDomainControllerLdapFilterAsync(string domain)
		{
			return await Task.FromResult($"(&(objectClass=domain)(objectClass=top)(dc={domain}))").ConfigureAwait(false);
		}

		[SuppressMessage("Style", "IDE0010:Add missing cases")]
		protected internal virtual async Task<string> CreateLdapFilterAsync(LdapConnection connection, string distinguishedName, IdentifierKind identifierKind, ClaimsPrincipal principal)
		{
			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			string ldapFilter;

			// ReSharper disable SwitchStatementHandlesSomeKnownEnumValuesWithDefault
			switch(identifierKind)
			{
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

						var nameParts = nameClaim.Value.Split('\\');
						var domain = nameParts.FirstOrDefault();
						var domainControllerLdapFilter = await this.CreateDomainControllerLdapFilterAsync(domain).ConfigureAwait(false);

						// ReSharper disable PossibleNullReferenceException
						if(((SearchResponse)connection.SendRequest(new SearchRequest(distinguishedName, domainControllerLdapFilter, SearchScope.Base, "dc"))).Entries.Count == 0)
							throw new InvalidOperationException($"The name-claim \"{nameClaim.Value}\" has an invalid domain-part. The domain \"{domain}\" is invalid.");
						// ReSharper restore PossibleNullReferenceException

						var samAccountName = nameParts.LastOrDefault();
						ldapFilter = $"sAMAccountName={samAccountName}";

						break;
					}
				case IdentifierKind.SamAccountName:
					{
						var nameClaim = principal.Claims.FindFirstNameClaim();

						if(nameClaim == null)
							throw new InvalidOperationException("Could not find a name-claim.");

						if(connection == null)
							throw new ArgumentNullException(nameof(connection));

						var samAccountName = nameClaim.Value;
						ldapFilter = $"sAMAccountName={samAccountName}";

						break;
					}
				default:
					{
						throw new InvalidOperationException($"The identifier-kind {identifierKind} is invalid.");
					}
			}
			// ReSharper restore SwitchStatementHandlesSomeKnownEnumValuesWithDefault

			return await Task.FromResult($"(&(objectClass=person)(objectClass=user)({ldapFilter}))").ConfigureAwait(false);
		}

		public virtual async Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, IdentifierKind identifierKind, ClaimsPrincipal principal)
		{
			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			try
			{
				if(this.Options.Value.ActiveDirectory.Impersonate)
				{
					if(!(principal.Identity is WindowsIdentity windowsIdentity))
						throw new InvalidOperationException("The identity is not a windows-identity.");

					WindowsIdentity.RunImpersonated(windowsIdentity.AccessToken, () => this.GetAttributesInternalAsync(attributes, identifierKind, principal).Result);
				}

				return await this.GetAttributesInternalAsync(attributes, identifierKind, principal).ConfigureAwait(false);
			}
			catch(Exception exception)
			{
				throw new InvalidOperationException($"Could not get attributes for principal \"{principal.Identity?.Name}\".", exception);
			}
		}

		[SuppressMessage("Style", "IDE0063:Use simple 'using' statement")]
		protected internal virtual async Task<IDictionary<string, string>> GetAttributesInternalAsync(IEnumerable<string> attributes, IdentifierKind identifierKind, ClaimsPrincipal principal)
		{
			var domainName = await this.GetDomainNameAsync().ConfigureAwait(false);
			var distinguishedName = string.Join(',', domainName.Split('.').Select(part => $"dc={part}"));

			// ReSharper disable ConvertToUsingDeclaration
			using(var connection = await this.CreateConnectionAsync(domainName).ConfigureAwait(false))
			{
				var ldapFilter = await this.CreateLdapFilterAsync(connection, distinguishedName, identifierKind, principal).ConfigureAwait(false);

				return await this.GetAttributesInternalAsync(attributes, connection, distinguishedName, ldapFilter, SearchScope.Subtree).ConfigureAwait(false);
			}
			// ReSharper restore ConvertToUsingDeclaration
		}

		protected internal virtual async Task<IDictionary<string, string>> GetAttributesInternalAsync(IEnumerable<string> attributes, LdapConnection connection, string distinguishedName, string ldapFilter, SearchScope scope)
		{
			attributes = (attributes ?? Enumerable.Empty<string>()).ToArray();
			var attributesResult = new Dictionary<string, string>();

			var searchResultAttributes = (await this.GetSearchResultEntryAsync(attributes, connection, distinguishedName, ldapFilter, scope).ConfigureAwait(false))?.Attributes;

			// ReSharper disable All
			if(searchResultAttributes != null)
			{
				var searchResultAttributeNames = (searchResultAttributes.AttributeNames?.Cast<string>() ?? Enumerable.Empty<string>()).ToArray();

				foreach(var attribute in attributes)
				{
					if(!searchResultAttributeNames.Contains(attribute, StringComparer.OrdinalIgnoreCase))
						continue;

					var directoryAttribute = searchResultAttributes[attribute];
					var values = new List<string>();

					for(var i = 0; i < directoryAttribute.Count; i++)
					{
						var value = directoryAttribute[i];

						if(value != null)
							values.Add(value.ToString());
					}

					attributesResult.Add(attribute, string.Join(", ", values));
				}
			}
			// ReSharper restore All

			return attributesResult;
		}

		protected internal virtual async Task<string> GetDomainNameAsync()
		{
			return await Task.FromResult(IPGlobalProperties.GetIPGlobalProperties().DomainName).ConfigureAwait(false);
		}

		protected internal virtual async Task<SearchResultEntry> GetSearchResultEntryAsync(IEnumerable<string> attributes, LdapConnection connection, string distinguishedName, string ldapFilter, SearchScope scope)
		{
			if(connection == null)
				throw new ArgumentNullException(nameof(connection));

			var searchResponse = (SearchResponse)connection.SendRequest(new SearchRequest(distinguishedName, ldapFilter, scope, (attributes ?? Enumerable.Empty<string>()).ToArray()));

			return await Task.FromResult(searchResponse?.Entries.Cast<SearchResultEntry>().FirstOrDefault()).ConfigureAwait(false);
		}

		#endregion
	}
}