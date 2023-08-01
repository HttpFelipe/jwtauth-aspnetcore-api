using JwtWebApi.Configurations;
using JwtWebApi.Data;
using JwtWebApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JwtWebApi
{
	public class Program
	{
		public static void Main(string[] args)
		{
			var builder = WebApplication.CreateBuilder(args);

			// Add services to the container.

			builder.Services.AddControllers();
			// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
			builder.Services.AddEndpointsApiExplorer();
			builder.Services.AddSwaggerGen();

			builder.Services.AddDbContext<AppDbContext>(options =>
			options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

			builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection("JwtConfig"));

			var key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("JwtConfig:Secret").Value ?? null!);

			var tokenValidationParams = new TokenValidationParameters()
			{
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(key),
				ValidateIssuer = false,
				ValidateAudience = false,
				RequireExpirationTime = true,
				ValidateLifetime = true
			};

			builder.Services.AddAuthentication(options =>
			{
				options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
				options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			})
			.AddJwtBearer(jwt =>
			{
				jwt.SaveToken = true;
				jwt.TokenValidationParameters = tokenValidationParams;
			});

			builder.Services.AddSingleton(tokenValidationParams);

			builder.Services.AddDefaultIdentity<IdentityUser>(options =>
			options.SignIn.RequireConfirmedAccount = false).AddEntityFrameworkStores<AppDbContext>();

			builder.Services.Configure<IdentityOptions>(options =>
			{
				options.Password.RequireDigit = true;
				options.Password.RequireLowercase = false;
				options.Password.RequireNonAlphanumeric = false;
				options.Password.RequireUppercase = false;
				options.Password.RequiredLength = 6;
				options.Password.RequiredUniqueChars = 1;
			});

			var app = builder.Build();

			// Configure the HTTP request pipeline.
			if (app.Environment.IsDevelopment())
			{
				app.UseSwagger();
				app.UseSwaggerUI();
			}

			app.UseHttpsRedirection();

			app.UseAuthentication();

			app.UseAuthorization();

			app.MapControllers();

			app.Run();
		}
	}
}