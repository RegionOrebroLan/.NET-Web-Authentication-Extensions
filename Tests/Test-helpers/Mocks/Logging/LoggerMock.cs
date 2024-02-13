using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace TestHelpers.Mocks.Logging
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

		public virtual LogLevelEnabledMode EnabledMode { get; set; }
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
			if(this.EnabledMode == LogLevelEnabledMode.Configuration)
				return this.InternalLogger.IsEnabled(logLevel);

			return this.EnabledMode == LogLevelEnabledMode.Enabled;
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

			this.InternalLogger.Log(logLevel, eventId, state, exception, formatter);
		}

		#endregion
	}
}