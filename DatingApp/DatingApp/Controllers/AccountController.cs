using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DatingApp.Data;
using DatingApp.Entities;
using Microsoft.AspNetCore.Mvc;

namespace DatingApp.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        public AccountController(DataContext context)
        {
            _context = context;

        }

        [HttpPost("register")]
        public async Task<ActionResult<AppUser>>Register(string username,string password)
        {
            //insialisation class de hash 
            using var hmac =new HMACSHA512();

            var user = new AppUser
            {
                UserName= username,
                //passwordHash :byte[] convert password:string => byte[]
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);

            await _context.SaveChangesAsync(); 

            return user;
        }
    }
}