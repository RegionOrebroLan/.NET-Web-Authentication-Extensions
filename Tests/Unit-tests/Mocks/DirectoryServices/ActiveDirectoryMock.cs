using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using RegionOrebroLan.Web.Authentication.DirectoryServices;

namespace UnitTests.Mocks.DirectoryServices
{
	public class ActiveDirectoryMock : IActiveDirectory
	{
		#region Properties

		public virtual IDictionary<string, IDictionary<string, string>> Result { get; } = new Dictionary<string, IDictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

		#endregion

		#region Methods

		public virtual async Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, string identifier, IdentifierKind identifierKind)
		{
			return await this.GetAttributesInternalAsync(attributes);
		}

		public virtual async Task<IDictionary<string, string>> GetAttributesAsync(IEnumerable<string> attributes, IdentifierKind identifierKind, ClaimsPrincipal principal)
		{
			return await this.GetAttributesInternalAsync(attributes);
		}

		protected internal virtual async Task<IDictionary<string, string>> GetAttributesInternalAsync(IEnumerable<string> attributes)
		{
			return (await this.GetUserAttributesInternalAsync(attributes)).FirstOrDefault().Value;
		}

		public virtual async Task<IDictionary<string, IDictionary<string, string>>> GetUserAttributesAsync(IEnumerable<string> attributes, string filter)
		{
			return await this.GetUserAttributesInternalAsync(attributes);
		}

		protected internal virtual async Task<IDictionary<string, IDictionary<string, string>>> GetUserAttributesInternalAsync(IEnumerable<string> attributes)
		{
			attributes = (attributes ?? Enumerable.Empty<string>()).ToHashSet(StringComparer.OrdinalIgnoreCase);
			var result = new Dictionary<string, IDictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

			foreach(var (distinguishedName, items) in this.Result)
			{
				var resultAttributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

				foreach(var attribute in attributes)
				{
					foreach(var (key, value) in items)
					{
						if(string.Equals(attribute, key, StringComparison.OrdinalIgnoreCase))
							resultAttributes.Add(key, value);
					}
				}

				result.Add(distinguishedName, resultAttributes);
			}

			return await Task.FromResult(result);
		}

		#endregion
	}
}