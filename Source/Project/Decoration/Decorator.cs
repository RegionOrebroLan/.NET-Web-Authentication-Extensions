using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc />
	public abstract class Decorator : IDecorator
	{
		#region Constructors

		protected Decorator(ILoggerFactory loggerFactory)
		{
			if(loggerFactory == null)
				throw new ArgumentNullException(nameof(loggerFactory));

			this.Logger = loggerFactory.CreateLogger(this.GetType());
		}

		#endregion

		#region Properties

		protected internal virtual ILogger Logger { get; }

		#endregion

		#region Methods

		public virtual async Task InitializeAsync(IConfigurationSection optionsConfiguration)
		{
			optionsConfiguration?.Bind(this, binderOptions => { binderOptions.BindNonPublicProperties = true; });

			await Task.CompletedTask.ConfigureAwait(false);
		}

		#endregion
	}
}