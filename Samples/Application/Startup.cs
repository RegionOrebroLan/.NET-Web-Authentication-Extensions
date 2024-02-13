using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RegionOrebroLan;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Security.Cryptography;
using RegionOrebroLan.Web.Authentication.DependencyInjection.Extensions;

namespace Application
{
	public class Startup
	{
		#region Constructors

		public Startup(IConfiguration configuration, IHostEnvironment hostEnvironment)
		{
			this.Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
			this.HostEnvironment = hostEnvironment ?? throw new ArgumentNullException(nameof(hostEnvironment));
		}

		#endregion

		#region Properties

		public virtual IConfiguration Configuration { get; }
		public virtual IHostEnvironment HostEnvironment { get; }

		#endregion

		#region Methods

		public virtual void Configure(IApplicationBuilder applicationBuilder)
		{
			ArgumentNullException.ThrowIfNull(applicationBuilder);

			applicationBuilder
				.UseDeveloperExceptionPage()
				.UseStaticFiles()
				.UseRouting()
				.UseAuthentication()
				.UseAuthorization()
				.UseEndpoints(endpoints => { endpoints.MapDefaultControllerRoute(); });
		}

		public virtual void ConfigureServices(IServiceCollection services)
		{
			ArgumentNullException.ThrowIfNull(services);

			//// We could skip the configuration of cookie-authentication in the configuration-file (appsettings.json) and instead do:
			//services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
			//	.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
			//	{
			//		options.LoginPath = new PathString("/Account/SignIn/");
			//		options.LogoutPath = new PathString("/Account/SignOut/");
			//	})
			//	.Configure(this.Configuration);

			services.AddAuthentication(this.CreateCertificateResolver(), this.Configuration, new InstanceFactory());
			services.AddControllersWithViews();
		}

		protected internal virtual ICertificateResolver CreateCertificateResolver()
		{
			var services = new ServiceCollection();

			services.AddSingleton(AppDomain.CurrentDomain);
			services.AddSingleton<FileCertificateResolver>();
			services.AddSingleton(this.HostEnvironment);
			services.AddSingleton<IApplicationDomain, ApplicationHost>();
			services.AddSingleton<ICertificateResolver, CertificateResolver>();
			services.AddSingleton<StoreCertificateResolver>();

			return services.BuildServiceProvider().GetRequiredService<ICertificateResolver>();
		}

		#endregion
	}
}