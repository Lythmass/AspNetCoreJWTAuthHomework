using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Reddit.Models;

namespace Reddit
{
    public class ApplicationDbContext: IdentityUserContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> dbContextOptions): base(dbContextOptions)
        {
        }

        public DbSet<Post> Posts { get; set; }
        public DbSet<User> Users { get; set; }
        public DbSet<Comment> Comments { get; set; }
        public DbSet<Community> Communities { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Community>(entity =>
            {
                entity.HasOne(c => c.Owner)
                      .WithMany(u => u.OwnedCommunities)
                      .HasForeignKey(e => e.OwnerId)
                      .OnDelete(DeleteBehavior.SetNull); // on delete


                entity.HasMany(c => c.Subscribers)
                      .WithMany(u => u.SubscribedCommunities);
            });

            base.OnModelCreating(modelBuilder);
        }
    }
}
