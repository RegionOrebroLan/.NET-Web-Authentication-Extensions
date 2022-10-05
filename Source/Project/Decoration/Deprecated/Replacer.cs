using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Decoration.Deprecated
{
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	[Obsolete("This decorator is deprecated. Use RegionOrebroLan.Web.Authentication.Decoration.ReplacementDecorator instead.")]
	public class Replacer : BasicReplacer
	{
		#region Constructors

		public Replacer(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		public override IDictionary<string, string> Replacements { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		#endregion
	}
}