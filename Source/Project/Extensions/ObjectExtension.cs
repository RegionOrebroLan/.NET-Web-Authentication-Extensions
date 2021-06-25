namespace RegionOrebroLan.Web.Authentication.Extensions
{
	public static class ObjectExtension
	{
		#region Methods

		public static string ToStringRepresentation(this object instance)
		{
			return instance switch
			{
				null => "null",
				string value => $"\"{value}\"",
				_ => instance.ToString(),
			};
		}

		#endregion
	}
}