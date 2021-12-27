using System;
using RegionOrebroLan.Web.Authentication.Certificate;
using RegionOrebroLan.Web.Authentication.Configuration;

namespace RegionOrebroLan.Web.Authentication.DependencyInjection.Registration
{
	public class CertificateRegistrator : Registrator
	{
		#region Methods

		public override void Add(ExtendedAuthenticationBuilder authenticationBuilder, string name, SchemeRegistrationOptions schemeRegistrationOptions)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			if(schemeRegistrationOptions == null)
				throw new ArgumentNullException(nameof(schemeRegistrationOptions));

			//authenticationBuilder.Services.Configure<CertificateAuthenticationOptions>(name, options => { this.Bind(configuration, options, schemeRegistrationOptions); });

			authenticationBuilder.AddCertificate(name, schemeRegistrationOptions.DisplayName, options => { this.Bind(authenticationBuilder, options, schemeRegistrationOptions); });
		}

		#endregion
	}
}