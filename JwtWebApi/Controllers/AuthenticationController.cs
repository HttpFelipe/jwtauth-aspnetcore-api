using JwtWebApi.Configurations;
using JwtWebApi.Data;
using JwtWebApi.Models;
using JwtWebApi.Models.DTOs;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using MimeKit.Text;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;

namespace JwtWebApi.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthenticationController : ControllerBase
	{
		private readonly UserManager<IdentityUser> _userManager;
		private readonly IConfiguration _configuration;
		private readonly TokenValidationParameters _tokenValidationParameters;
		private readonly AppDbContext _context;

		public AuthenticationController(UserManager<IdentityUser>
			userManager, IConfiguration configuration,
			AppDbContext context, TokenValidationParameters tokenValidationParameters)
		{
			_userManager = userManager;
			_configuration = configuration;
			_context = context;
			_tokenValidationParameters = tokenValidationParameters;
		}

		[HttpPost]
		[Route("Register")]
		public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto)
		{
			if (ModelState.IsValid && requestDto.Email != null)
			{
				var userExist = await _userManager.FindByEmailAsync(requestDto.Email);
				if (userExist != null)
				{
					return BadRequest(new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
								"Email already exist"
						}
					});
				}
				if (requestDto.Password is null)
				{
					return BadRequest();
				}

				if (requestDto.Password.Length < 6)
				{
					return BadRequest("Password needs to be at least 6 characters long");
				}

				var newUser = new IdentityUser()
				{
					Email = requestDto.Email,
					UserName = requestDto.Email,
					EmailConfirmed = false
				};

				var isCreated = await _userManager.CreateAsync(newUser, requestDto.Password);
				if (isCreated.Succeeded)
				{
					var code = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);

					var callbackUrl = Request.Scheme + "://" + Request.Host + Url.Action("ConfirmEmail", "Authentication",
						new { userId = newUser.Id, code = code });

					var body = $"Please confirm your email adress: {callbackUrl}";

					var result = SendEmail(body, "Email from Ehereal Email");

					if (result)
					{
						return Ok("Please verify your email, through the verification email we have just sent.");
					}

					return Ok("Please request an email verification link");
				}

				return BadRequest(new AuthResult()
				{
					Result = false,
					Errors = new List<string>()
					{
						"Server error"
					}
				});
			}
			return BadRequest();
		}

		[HttpGet]
		[Route("ConfirmEmail")]
		public async Task<IActionResult> ConfirmEmail(string userId, string code)
		{
			if (userId == null || code == null)
			{
				return BadRequest(new AuthResult()
				{
					Errors = new List<string>()
					{
						"Invalid email confirmation url"
					}
				});
			}

			var user = await _userManager.FindByIdAsync(userId);
			if (user == null)
			{
				return BadRequest(new AuthResult()
				{
					Errors = new List<string>()
					{
						"Invalid email parameter"
					}
				});
			}

			var result = await _userManager.ConfirmEmailAsync(user, code);
			var status = result.Succeeded ? "Thanks for confirming your email" : "Your email is not confirmed, please try again later";
			return Ok(status);
		}

		[HttpPost]
		[Route("Login")]
		public async Task<IActionResult> Login([FromBody] UserLoginRequestDto loginRequest)
		{
			if (ModelState.IsValid && loginRequest.Email != null && loginRequest.Password != null)
			{
				var existingUser = await _userManager.FindByEmailAsync(loginRequest.Email);

				if (existingUser == null)
				{
					return BadRequest(new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Invalid payload"
						}
					});
				}

				if (!existingUser.EmailConfirmed)
				{
					return BadRequest(new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Email needs to be confirmed"
						}
					});
				}

				var isCorrect = await _userManager.CheckPasswordAsync(existingUser, loginRequest.Password);

				if (!isCorrect)
				{
					return BadRequest(new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Invalid credentials"
						}
					});
				}
				var jwtToken = await GenerateJwtToken(existingUser);
				return Ok(jwtToken);
			}
			return BadRequest(new AuthResult()
			{
				Result = false,
				Errors = new List<string>()
				{
					"Invalid payload"
				}
			});
		}

		private async Task<AuthResult?> GenerateJwtToken(IdentityUser user)
		{
			var jwtTokenHandler = new JwtSecurityTokenHandler();

			var secretValue = _configuration.GetSection("JwtConfig:Secret").Value;
			var expiryTimeFrame = _configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value;

			if (secretValue != null && user.Email != null)
			{
				var key = secretValue?.Length > 0 ? Encoding.UTF8.GetBytes(secretValue) : null;

				var tokenDescriptor = new SecurityTokenDescriptor()
				{
					Subject = new ClaimsIdentity(new[]
				{
						new Claim("Id", user.Id),
						new Claim(JwtRegisteredClaimNames.Sub, user.Email),
						new Claim(JwtRegisteredClaimNames.Email, user.Email),
						new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
						new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
					}),
					//Passing a default value to Expires if the JwtConfig:ExpiryTimeFrame is null
					Expires = DateTime.UtcNow.Add(TimeSpan.Parse(expiryTimeFrame ?? "1:00:00")),
					SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
				};

				var token = jwtTokenHandler.CreateToken(tokenDescriptor);
				var jwtToken = jwtTokenHandler.WriteToken(token);

				var refreshToken = new RefreshToken()
				{
					JwtId = token.Id,
					Token = RandomStringGeneration(23),
					AddedDate = DateTime.UtcNow,
					ExpiryDate = DateTime.UtcNow.AddMonths(6),
					IsRevoked = false,
					IsUsed = false,
					UserId = user.Id
				};

				await _context.RefreshTokens.AddAsync(refreshToken);
				await _context.SaveChangesAsync();

				return new AuthResult()
				{
					Token = jwtToken,
					RefreshToken = refreshToken.Token,
					Result = true
				};
			}

			return null;
		}

		[HttpPost]
		[Route("RefreshToken")]
		public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
		{
			if (ModelState.IsValid)
			{
				var result = await VerifyAndGenerateToken(tokenRequest);

				if (result == null)
				{
					return BadRequest(new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Invalid tokens"
						}
					});
				}
				return Ok(result);
			}
			return BadRequest(new AuthResult()
			{
				Result = false,
				Errors = new List<string>()
				{
					"Invalid parameters"
				}
			});
		}

		private async Task<AuthResult?> VerifyAndGenerateToken(TokenRequest tokenRequest)
		{
			var jwtTokenHandler = new JwtSecurityTokenHandler();
			try
			{
				_tokenValidationParameters.ValidateLifetime = true;

				var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);

				if (validatedToken is JwtSecurityToken jwtSecurityToken)
				{
					var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
						StringComparison.InvariantCultureIgnoreCase);

					if (!result)
					{
						return null;
					}
				}

				var expiryClaim = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp);
				if (expiryClaim != null && long.TryParse(expiryClaim.Value, out var utcExpiryDate))
				{
					var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);
					if (DateTime.UtcNow >= expiryDate)
					{
						return new AuthResult()
						{
							Result = false,
							Errors = new List<string>()
							{
								"Expired token"
							}
						};
					}
				}

				var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

				if (storedToken == null)
				{
					return new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Invalid tokens"
						}
					};
				}
				if (storedToken.IsUsed)
				{
					return new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Invalid tokens"
						}
					};
				}
				if (storedToken.IsRevoked)
				{
					return new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Invalid tokens"
						}
					};
				}

				var jtiClaim = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti);
				var jti = jtiClaim?.Value ?? string.Empty;

				if (storedToken.JwtId != jti)
				{
					return new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Invalid tokens"
						}
					};
				}
				if (storedToken.ExpiryDate < DateTime.UtcNow)
				{
					return new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Expired tokens"
						}
					};
				}
				storedToken.IsUsed = true;
				_context.RefreshTokens.Update(storedToken);
				await _context.SaveChangesAsync();

				if (storedToken == null || string.IsNullOrEmpty(storedToken.UserId))
				{
					return new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Invalid token"
						}
					};
				}

				var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);

				if (dbUser == null)
				{
					return new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"User not found"
						}
					};
				}

				return await GenerateJwtToken(dbUser);
			}
			catch (Exception)
			{
				return new AuthResult()
				{
					Result = false,
					Errors = new List<string>()
						{
							"Server error"
						}
				};
			}
		}

		private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
		{
			var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
			dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
			return dateTimeVal;
		}

		private bool SendEmail(string body, string emailTarget)
		{
			try
			{
				var email = new MimeMessage();
				email.From.Add(MailboxAddress.Parse("Email from Ehereal Email"));
				email.To.Add(MailboxAddress.Parse(emailTarget));
				email.Subject = "Verify your email";
				email.Body = new TextPart(TextFormat.Html) { Text = body };

				using var smtp = new MailKit.Net.Smtp.SmtpClient();
				smtp.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
				smtp.Authenticate("Email from Ehereal Email", "Password from Etheral Email");
				smtp.Send(email);
				smtp.Disconnect(true);

				return true;
			}
			catch (Exception)
			{
				return false;
			}
		}

		private string RandomStringGeneration(int length)
		{
			var random = new Random();
			var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz_";
			return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
		}
	}
}