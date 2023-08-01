using JwtWebApi.Data;
using JwtWebApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtWebApi.Controllers
{
	[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
	[Route("api/[controller]")]
	[ApiController]
	public class TeamsController : ControllerBase
	{
		private readonly AppDbContext _context;

		public TeamsController(AppDbContext context)
		{
			_context = context;
		}

		[HttpGet]
		public async Task<IActionResult> Get()
		{
			var teams = await _context.Teams.ToListAsync();
			return Ok(teams);
		}

		[HttpGet("{id}")]
		public async Task<IActionResult> Get(int id)
		{
			var team = await _context.Teams.FirstOrDefaultAsync(t => t.Id == id);
			if (team == null)
			{
				return BadRequest("Invalid Id");
			}
			return Ok(team);
		}

		[HttpPost]
		public async Task<IActionResult> Post(Team team)
		{
			await _context.Teams.AddAsync(team);
			await _context.SaveChangesAsync();
			return CreatedAtAction("Get", team.Id, team);
		}

		[HttpPut("{id}")]
		public async Task<IActionResult> Put(int id, Team teamModified)
		{
			var team = await _context.Teams.FirstOrDefaultAsync(t => t.Id == id);
			if (team == null)
			{
				return BadRequest("Invalid id");
			}

			team.Name = teamModified.Name;
			team.Country = teamModified.Country;
			team.Game = teamModified.Game;

			_context.Update(team);
			await _context.SaveChangesAsync();

			return NoContent();
		}

		[HttpDelete("{id}")]
		public async Task<IActionResult> Delete(int id)
		{
			var team = await _context.Teams.FirstOrDefaultAsync(t => t.Id == id);
			if (team == null)
			{
				return BadRequest("Invalid id");
			}

			_context.Teams.Remove(team);
			await _context.SaveChangesAsync();

			return NoContent();
		}
	}
}