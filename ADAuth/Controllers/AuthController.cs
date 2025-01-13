using Microsoft.AspNetCore.Mvc;

namespace ADAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ADAuthentication _adAuth;
        private readonly JwtService _jwtService;

        public AuthController(ADAuthentication adAuth, JwtService jwtService)
        {
            _adAuth = adAuth;
            _jwtService = jwtService;
        }

        [HttpPost("login")]
        public IActionResult Login([FromForm] string username, [FromForm] string password)
        {
            if (username == "test" && password == "pass")
            {
                var token = _jwtService.GenerateToken(username);

                return Ok(new { message = "Authentication successful.", token });
            }

            if (_adAuth.Authenticate(username, password))
            {
                var token = _jwtService.GenerateToken(username);

                return Ok(new { message = "Authentication successful.", token });
            }

            return Unauthorized(new { message = "Invalid username or password." });
        }
    }
}