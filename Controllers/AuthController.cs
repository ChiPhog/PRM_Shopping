using FPTMOBILE.DTO;
using FPTMOBILE.Models;
using FptMobileApi.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Google.Apis.Auth;

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
        public async Task<IActionResult> Login([FromForm] LoginDTO model)
        {
            var user = await _context.kh_tbl
                .FirstOrDefaultAsync(u => u.acc_kh == model.acc_kh);

            if (user != null)
            {
                var hasher = new PasswordHasher<User>();
                var result = hasher.VerifyHashedPassword(user, user.pass_kh, model.pass_kh);

                if (result == PasswordVerificationResult.Success)
                {
                    return Ok(new { status = "success", message = "Login successful" });
                }
            }

            return BadRequest(new { status = "error", message = "Invalid username or password" });
        }

        [HttpPost("google-login")]
        public async Task<IActionResult> GoogleLogin([FromBody] string idToken)
        {
            try
            {
                var payload = await GoogleJsonWebSignature.ValidateAsync(idToken, new GoogleJsonWebSignature.ValidationSettings()
                {
                    Audience = new[] { "1053282566534-4gjhnt1haroj1k4lab02iedetf4gq49b.apps.googleusercontent.com" } // giống với Android
                });

                // payload.Email, payload.Name, payload.Subject (Google user ID)
                // Tùy bạn xử lý: tạo user mới hoặc đăng nhập user cũ
                var user = await _context.kh_tbl.FirstOrDefaultAsync(u => u.acc_kh == payload.Email);
                if (user == null)
                {
                    user = new User
                    {
                        acc_kh = payload.Email,
                        pass_kh = "" // bạn có thể để rỗng hoặc đánh dấu là Google user
                    };
                    _context.kh_tbl.Add(user);
                    await _context.SaveChangesAsync();
                }

                return Ok(new { status = "success", message = "Google login successful" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { status = "error", message = "Invalid token", detail = ex.Message });
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromForm] RegisterDTO model)
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

            // Hash password
            var hasher = new PasswordHasher<User>();
            var newUser = new User
            {
                acc_kh = model.acc_kh
            };
            newUser.pass_kh = hasher.HashPassword(newUser, model.pass_kh);

            _context.kh_tbl.Add(newUser);
            await _context.SaveChangesAsync();

            return Ok(new { status = "success", message = "Registration successful" });
        }

    }




}