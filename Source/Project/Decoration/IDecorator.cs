using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	public interface IDecorator
	{
		#region Methods

		Task InitializeAsync(IConfigurationSection optionsConfiguration);

		#endregion
	}
}