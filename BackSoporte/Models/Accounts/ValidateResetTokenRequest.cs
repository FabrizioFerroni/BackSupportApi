using System.ComponentModel.DataAnnotations;

namespace BackSoporte.Models.Accounts
{
    public class ValidateResetTokenRequest
    {
        [Required]
        public string Token { get; set; }
    }
}
