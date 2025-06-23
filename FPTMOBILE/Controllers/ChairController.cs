using FPTMOBILE.Models;
using FptMobileApi.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[ApiController]
[Route("api/[controller]")]
public class ChairController : ControllerBase
{
    private readonly AppDbContext _context;

    public ChairController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<Chairs>>> GetAllChairs()
    {
        return await _context.Chairs.ToListAsync();
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Chairs>> GetChairById(Guid id)
    {
        var chair = await _context.Chairs.FindAsync(id);
        if (chair == null)
        {
            return NotFound();
        }
        return chair;
    }

    [HttpPost]
    public async Task<ActionResult<Chairs>> CreateChair(Chairs chair)
    {
        chair.id = Guid.NewGuid(); // Nếu bạn không dùng Identity column
        _context.Chairs.Add(chair);
        await _context.SaveChangesAsync();
        return CreatedAtAction(nameof(GetChairById), new { id = chair.id }, chair);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateChair(Guid id, Chairs chair)
    {
        if (id != chair.id)
        {
            return BadRequest();
        }

        _context.Entry(chair).State = EntityState.Modified;
        try
        {
            await _context.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException)
        {
            if (!_context.Chairs.Any(e => e.id == id))
                return NotFound();
            throw;
        }

        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteChair(Guid id)
    {
        var chair = await _context.Chairs.FindAsync(id);
        if (chair == null)
        {
            return NotFound();
        }

        _context.Chairs.Remove(chair);
        await _context.SaveChangesAsync();
        return NoContent();
    }
}
