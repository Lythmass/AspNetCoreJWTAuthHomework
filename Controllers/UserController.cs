using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Reddit.Dtos;
using Reddit.Models;
using Reddit.Services;

namespace Reddit.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly TokenService _tokenService;

        public UserController(ApplicationDbContext context, UserManager<ApplicationUser> userManager, TokenService tokenService)
        {
            _context = context;
            _userManager = userManager;
            _tokenService = tokenService;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(CreateAccount createAccount)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _userManager.CreateAsync(new ApplicationUser { 
                UserName = createAccount.UserName, 
                Email = createAccount.Email, 
                RefreshToken = _tokenService.GenerateRefreshToken(), 
                RefreshTokenExpiryTime = DateTime.Now.AddDays(14),
            }, createAccount.Password);

            if (result.Succeeded) return CreatedAtAction(nameof(Register), createAccount);

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(error.Code, error.Description);
            }

            return BadRequest(ModelState);
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(AuthenticateAccount authenticateAccount)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(authenticateAccount.Email!);

            if (user == null) return BadRequest("Incorrect Email");

            var isPasswordValid = await _userManager.CheckPasswordAsync(user, authenticateAccount.Password!);

            if (!isPasswordValid) return BadRequest("Incorrect Password");

            var accessToken = _tokenService.CreateToken(user);
            await _context.SaveChangesAsync();

            return Ok(new AuthenticationResponse
            {
                Username = user.UserName,
                Email = user.Email,
                Token = accessToken,
                RefreshToken = user.RefreshToken,
            });
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenModel tokenModel)
        {
            if (tokenModel == null) return BadRequest("Invalid Client");

            var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshToken == tokenModel.RefreshToken);

            if (user == null || user.RefreshTokenExpiryTime <= DateTime.Now) return BadRequest("Invalid Refresh Token");

            var newAccessToken = _tokenService.CreateToken(user);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(TokenService.RefreshTokenExpirationDays);

            await _userManager.UpdateAsync(user);

            return Ok(new
            {
                accessToken = newAccessToken,
                refreshToken = newRefreshToken,
            });
        }

        [HttpPost]
        public async Task<IActionResult> CreateAuthor(CreateUserDto createAuthorDto)
        {
            var author = new User
            {
                Name = createAuthorDto.Name
            };

            await _context.Users.AddAsync(author);
            await _context.SaveChangesAsync();
            return Ok();
        }


        [HttpGet]
        public async Task<ActionResult<IEnumerable<User>>> GetAuthors()
        {
            return await _context.Users.ToListAsync();
        }
        [HttpPost("JoinCommunity")]
        public async Task<IActionResult> JoinCommunity(int userId,int communityId)
        {
            var community = await _context.Communities.FindAsync(communityId);

            if (community == null)
            {
                return NotFound();
            }

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            user.SubscribedCommunities.Add(community);
            await _context.SaveChangesAsync();
            return Ok();
        }
    }
}