using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace RegionOrebroLan.Web.Authentication.Test.Mocks.Logging
{
	public class LoggerMock : ILogger
	{
		#region Constructors

		public LoggerMock(ILogger internalLogger, IList<LogMock> logs)
		{
			this.InternalLogger = internalLogger ?? throw new ArgumentNullException(nameof(internalLogger));
			this.Logs = logs ?? throw new ArgumentNullException(nameof(logs));
		}

		#endregion

		#region Properties

		public virtual bool Enabled { get; set; }
		protected virtual ILogger InternalLogger { get; }
		protected virtual IList<LogMock> Logs { get; }

		#endregion

		#region Methods

		public virtual IDisposable BeginScope<TState>(TState state)
		{
			return this.InternalLogger.BeginScope(state);
		}

		public virtual bool IsEnabled(LogLevel logLevel)
		{
			return this.Enabled;
		}

		public virtual void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
		{
			var message = formatter?.Invoke(state, exception);

			this.Logs.Add(new LogMock
			{
				Exception = exception,
				EventId = eventId,
				LogLevel = logLevel,
				Message = message,
				State = state
			});
		}

		#endregion
	}
}