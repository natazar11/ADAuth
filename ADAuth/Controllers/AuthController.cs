﻿using Microsoft.AspNetCore.Mvc;

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
        public IActionResult Login([FromBody]User user)
        {
            if (user.username == "test" && user.password == "pass")
            {
                var token = _jwtService.GenerateToken(user.username);

                return Ok(new { message = "Authentication successful.", token });
            }

            if (_adAuth.Authenticate(user.username, user.password))
            { 
                var token = _jwtService.GenerateToken(user.username);

                return Ok(new { message = "Authentication successful.", token });
            }

            return Unauthorized(new { message = "Invalid username or password." });
        }
    }
    public class User
    {
        public string username { get; set; }
        public string password { get; set; }
    }
}