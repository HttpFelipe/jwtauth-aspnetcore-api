using JwtWebApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JwtWebApi.Data
{
	public class AppDbContext : IdentityDbContext
	{
		public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
		{
		}

		public DbSet<Team> Teams { get; set; }
		public DbSet<RefreshToken> RefreshTokens { get; set; }
	}
}