namespace JwtWebApi.Models
{
	public class Team
	{
		public int Id { get; set; }
		public string Name { get; set; } = string.Empty;
		public string Country { get; set; } = string.Empty;
		public string Game { get; set; } = string.Empty;
	}
}