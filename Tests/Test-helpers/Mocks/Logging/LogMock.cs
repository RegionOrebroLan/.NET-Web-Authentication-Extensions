using System;
using Microsoft.Extensions.Logging;

namespace TestHelpers.Mocks.Logging
{
	public class LogMock
	{
		#region Properties

		public virtual EventId EventId { get; set; }
		public virtual Exception Exception { get; set; }
		public virtual LogLevel LogLevel { get; set; }
		public virtual string Message { get; set; }
		public virtual object State { get; set; }

		#endregion
	}
}