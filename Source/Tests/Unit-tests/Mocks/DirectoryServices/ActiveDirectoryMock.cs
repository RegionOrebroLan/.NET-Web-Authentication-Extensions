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

		public virtual IDictionary<string, string> Result { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

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
			var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

			foreach(var attribute in new HashSet<string>(attributes ?? Enumerable.Empty<string>(), StringComparer.OrdinalIgnoreCase))
			{
				foreach(var (key, value) in this.Result)
				{
					if(string.Equals(attribute, key, StringComparison.OrdinalIgnoreCase))
						result.Add(key, value);
				}
			}

			return await Task.FromResult(result);
		}

		#endregion
	}
}