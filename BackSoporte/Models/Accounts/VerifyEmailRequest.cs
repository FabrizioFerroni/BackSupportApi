using System.ComponentModel.DataAnnotations;

namespace BackSoporte.Models.Accounts
{
    public class VerifyEmailRequest
    {
        //[Required]
        public string Token { get; set; }
    }
}
