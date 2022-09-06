using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.DirectoryServices.Protocols.Configuration;
using RegionOrebroLan.Security.Cryptography;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.DependencyInjection.Registration;
using RegionOrebroLan.Web.Authentication.DirectoryServices;
using ConfigurationKeys = RegionOrebroLan.Web.Authentication.Configuration.ConfigurationKeys;

namespace RegionOrebroLan.Web.Authentication
{
	public class ExtendedAuthenticationBuilder : AuthenticationBuilder
	{
		#region Constructors

		public ExtendedAuthenticationBuilder(IServiceCollection services) : base(services) { }

		#endregion

		#region Properties

		public virtual ICertificateResolver CertificateResolver { get; set; }
		public virtual IConfiguration Configuration { get; set; }
		public virtual string ConfigurationKey { get; set; } = ConfigurationKeys.AuthenticationPath;
		public virtual IInstanceFactory InstanceFactory { get; set; }

		#endregion

		#region Methods

		public virtual ExtendedAuthenticationBuilder Configure()
		{
			var configurationSection = this.Configuration.GetSection(this.ConfigurationKey);
			this.Services.Configure<ExtendedAuthenticationOptions>(configurationSection);
			var extendedAuthenticationOptions = new ExtendedAuthenticationOptions();
			configurationSection.Bind(extendedAuthenticationOptions);

			foreach(var (key, value) in extendedAuthenticationOptions.SchemeRegistrations)
			{
				if(!value.Enabled)
					continue;

				var registrator = (Registrator)this.InstanceFactory.Create(value.Type);

				registrator.Add(this, key, value);
			}

			this.Services.TryAddTransient<ActiveDirectoryCallbackDecorator>();
			this.Services.TryAddTransient<CallbackDecorator>();
			this.Services.TryAddTransient<CertificateAuthenticationDecorator>();
			this.Services.TryAddTransient<DirectActiveDirectoryDecorator>();
			this.Services.TryAddSingleton<IActiveDirectory, ActiveDirectory>();
			this.Services.TryAddSingleton<IAuthenticationSchemeLoader, AuthenticationSchemeLoader>();
			this.Services.TryAddSingleton<IDecorationLoader, DecorationLoader>();
			this.Services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
			this.Services.TryAddSingleton<IParser<LdapConnectionOptions>, LdapConnectionStringParser>();
			this.Services.TryAddTransient<JwtToMicrosoftMapper>();
			this.Services.TryAddTransient<JwtToMicrosoftReplacer>();
			this.Services.TryAddTransient<Mapper>();
			this.Services.TryAddTransient<MicrosoftToJwtMapper>();
			this.Services.TryAddTransient<MicrosoftToJwtReplacer>();
			this.Services.TryAddTransient<NegotiateAuthenticationDecorator>();
			this.Services.TryAddTransient<OrganizationCallbackDecorator>();
			this.Services.TryAddTransient<Replacer>();
			this.Services.TryAddTransient<SithsCertificateSubjectExtractor>();

			return this;
		}

		#endregion
	}
}