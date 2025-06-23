using FPTMOBILE.Models;
using Microsoft.EntityFrameworkCore;

namespace FptMobileApi.Models
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> kh_tbl { get; set; }
        public DbSet<Chairs> Chairs { get; set; }
    }

   
}