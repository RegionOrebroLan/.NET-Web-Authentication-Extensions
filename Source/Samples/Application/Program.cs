using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace Application
{
	public static class Program
	{
		#region Methods

		public static IHostBuilder CreateHostBuilder(string[] args)
		{
			return Host.CreateDefaultBuilder(args)
				.ConfigureWebHostDefaults(webBuilder => { webBuilder.UseStartup<Startup>(); });
		}

		public static void Main(string[] args)
		{
			CreateHostBuilder(args).Build().Run();
		}

		#endregion
	}
}