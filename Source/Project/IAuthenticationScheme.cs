using System;

namespace RegionOrebroLan.Web.Authentication
{
	public interface IAuthenticationScheme
	{
		#region Properties

		string DisplayName { get; }
		bool Enabled { get; }
		Type HandlerType { get; }
		string Icon { get; }
		int Index { get; }
		bool Interactive { get; }
		AuthenticationSchemeKind Kind { get; }
		string Name { get; }
		bool SignOutSupport { get; }

		#endregion
	}
}