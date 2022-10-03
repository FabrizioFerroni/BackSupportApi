using BackSoporte.Entity;
using Microsoft.EntityFrameworkCore;
using System.Security.Principal;

namespace BackSoporte.Data
{
    public class ApplicationDbContext : DbContext
    {
        //public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        //{

        //}

        //public DbSet<Usuario> Usuarios { get; set; }

        public DbSet<Usuario> Usuarios { get; set; }

        private readonly IConfiguration Configuration;

        public ApplicationDbContext(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // connect to sql server database
            options.UseSqlServer(Configuration.GetConnectionString("WebApiDatabase"));
        }
    }
}
