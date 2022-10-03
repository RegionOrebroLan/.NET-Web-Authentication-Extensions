using System;

namespace RegionOrebroLan.Web.Authentication.Decoration.Deprecated
{
	[Obsolete(ObsoleteHelper.Message)]
	public class ClaimMapping
	{
		#region Properties

		/// <summary>
		/// The claim-type to map to. If null, the source will be used.
		/// </summary>
		public virtual string Destination { get; set; }

		/// <summary>
		/// The claim-type, or other special decorator-declaration, to map from.
		/// </summary>
		public virtual string Source { get; set; }

		#endregion
	}
}