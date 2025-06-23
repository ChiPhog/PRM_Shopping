using Microsoft.EntityFrameworkCore;

namespace FptMobileApi.Models
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> kh_tbl { get; set; }
    }

    public class User
    {
        public int Id { get; set; }
    	public required string acc_kh { get; set; } // Them required
    	public required string pass_kh { get; set; } // Them required
    }
}