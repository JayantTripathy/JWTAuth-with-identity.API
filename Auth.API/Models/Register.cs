using System.ComponentModel.DataAnnotations;

namespace Auth.API.Models
{
    public class Register
    {
        [Required(ErrorMessage ="User Name is required")]
        public string UserName { get; set; }
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }
        [Required(ErrorMessage = "Password is required")]
        public string Passowrd { get; set; }
    }
}
