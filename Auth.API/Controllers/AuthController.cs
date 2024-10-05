using Auth.API.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text;

namespace Auth.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;
        public AuthController(UserManager<IdentityUser> _userManager,
            RoleManager<IdentityRole> _roleManager, IConfiguration _configuration)
        {
            userManager = _userManager;
            roleManager = _roleManager;
            configuration = _configuration;
        }
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] Register model)
        {
            var userExists = await userManager.FindByNameAsync(model.UserName);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User alredy exists" });
            }
            IdentityUser user = new()
            {
                Email = model.Email,
                UserName = model.UserName,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            var result = await userManager.CreateAsync(user, model.Passowrd);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Creation is falied ! Please check the details and try again" });
            return Ok(new Response { Status = "Success", Message = "User has been Created" });
        }
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            var user = await userManager.FindByNameAsync(model.UserName);
            if (user != null && await userManager.CheckPasswordAsync(user, model.Passowrd))
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                // JWT Token
                var token = GetToken(authClaims);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] Register model)
        {
            var userExists = await userManager.FindByNameAsync(model.UserName);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User alredy exists" });
            }
            IdentityUser user = new()
            {
                Email = model.Email,
                UserName = model.UserName,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            var result = await userManager.CreateAsync(user, model.Passowrd);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Creation is falied ! Please check the details and try again" });
            if(!await roleManager.RoleExistsAsync(UserRole.Admin))
            {
                await roleManager.CreateAsync(new IdentityRole(UserRole.Admin));
            }
            if (!await roleManager.RoleExistsAsync(UserRole.User))
            {
                await roleManager.CreateAsync(new IdentityRole(UserRole.User));
            }
            if (await roleManager.RoleExistsAsync(UserRole.Admin))
            {
                await userManager.AddToRoleAsync(user, UserRole.Admin);
            }
            if (await roleManager.RoleExistsAsync(UserRole.User))
            {
                await userManager.AddToRoleAsync(user, UserRole.User);
            }

            return Ok(new Response { Status = "Success", Message = "User has been Created" });
        }

        private JwtSecurityToken GetToken(List<Claim> autheClaim)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWTAuth:SecretKey"]));
            var token = new JwtSecurityToken(
                issuer: configuration["JWTAuth:ValidateIssuerUrl"],
                audience: configuration["JWTAuth:ValidateAudienceUrl"],
                expires: DateTime.Now.AddMinutes(5),
                claims: autheClaim,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }
    }
}
