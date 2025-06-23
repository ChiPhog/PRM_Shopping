using FPTMOBILE.Models;
using FptMobileApi.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FptMobileApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;

        public AuthController(AppDbContext context)
        {
            _context = context;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromForm] LoginModel model)
        {
            var user = await _context.kh_tbl
                .FirstOrDefaultAsync(u => u.acc_kh == model.acc_kh && u.pass_kh == model.pass_kh);

            if (user != null)
            {
                return Ok(new { status = "success", message = "Login successful" });
            }
            return BadRequest(new { status = "error", message = "Invalid username or password" });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromForm] RegisterModel model)
        {
            if (model.pass_kh != model.repass_kh)
            {
                return BadRequest(new { status = "error", message = "Passwords do not match" });
            }

            var existingUser = await _context.kh_tbl
                .FirstOrDefaultAsync(u => u.acc_kh == model.acc_kh);

            if (existingUser != null)
            {
                return BadRequest(new { status = "error", message = "Username already exists" });
            }

            var newUser = new User
            {
                acc_kh = model.acc_kh,
                pass_kh = model.pass_kh
            };

            _context.kh_tbl.Add(newUser);
            await _context.SaveChangesAsync();

            return Ok(new { status = "success", message = "Registration successful" });
        }
    }

    public class LoginModel
    {
        public required string acc_kh { get; set; }
        public required string pass_kh { get; set; }
    }

    public class RegisterModel
    {
        public required string acc_kh { get; set; }
        public required string pass_kh { get; set; }
        public required string repass_kh { get; set; }
    }
}