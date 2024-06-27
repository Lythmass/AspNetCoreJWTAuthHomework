using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Reddit.Dtos;
using Reddit.Mapper;
using Reddit.Models;


namespace Reddit.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CommunityController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;

        public CommunityController(ApplicationDbContext context, IMapper mapper)
        {
            _context = context;
            _mapper = mapper;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<Community>>> GetCommunities()
        {
            return await _context.Communities.ToListAsync();
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<Community>> GetCommunity(int id)
        {
            var community = await _context.Communities.FindAsync(id);

            if(community == null)
            {
                return NotFound();
            }

            return community;
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> CreateCommunity(CreateCommunityDto communityDto)
        {
                var community = _mapper.toCommunity(communityDto);

                await _context.Communities.AddAsync(community);
                await _context.SaveChangesAsync();
                return Ok();
        }

        [HttpDelete("{id}")]
        [Authorize]
        public async Task<IActionResult> DeleteCommunity(int id)
        {
            var community = await _context.Communities.FindAsync(id);
            if (community == null)
            {
                return NotFound();
            }

            _context.Communities.Remove(community);
            await _context.SaveChangesAsync();

            return Ok();
        }

        [HttpPut("{id}")]
        [Authorize]
        public async Task<IActionResult> PutCommunity (int id, Community community)
        {
            if (!CommunityExists(id))
            {
                return NotFound();
            }

            _context.Entry(community).State = EntityState.Modified;
            await _context.SaveChangesAsync();

            return Ok();
        }

        private bool CommunityExists(int id) => _context.Communities.Any(e => e.Id == id);
    }
}
