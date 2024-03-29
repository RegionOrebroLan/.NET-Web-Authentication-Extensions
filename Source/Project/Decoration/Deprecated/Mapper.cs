using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;

namespace RegionOrebroLan.Web.Authentication.Decoration.Deprecated
{
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	[Obsolete(ObsoleteHelper.Message)]
	public class Mapper : BasicMapper
	{
		#region Constructors

		public Mapper(ILoggerFactory loggerFactory) : base(loggerFactory) { }

		#endregion

		#region Properties

		public override IDictionary<string, string> Map { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		#endregion
	}
}