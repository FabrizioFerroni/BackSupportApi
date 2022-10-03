using BackSoporte.Authorization;
using BackSoporte.Entity;
using BackSoporte.Models.Accounts;
using BackSoporte.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace BackSoporte.Controllers;
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class UsuarioController : BaseController
    {
    private readonly IUsuarioService _accountService;

    public UsuarioController(IUsuarioService accountService)
    {
        _accountService = accountService;
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public ActionResult<AuthenticateResponse> Authenticate(AuthenticateRequest model)
    {
        var response = _accountService.Authenticate(model, ipAddress());
        setTokenCookie(response.RefreshToken);
        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("refresh-token")]
    public ActionResult<AuthenticateResponse> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = _accountService.RefreshToken(refreshToken, ipAddress());
        setTokenCookie(response.RefreshToken);
        return Ok(response);
    }

    [HttpPost("revoke-token")]
    public IActionResult RevokeToken(RevokeTokenRequest model)
    {
        // accept token from request body or cookie
        var token = model.Token ?? Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(token))
            return BadRequest(new { message = "El token es requerido" });

        // users can revoke their own tokens and admins can revoke any tokens
        if (!Account.OwnsToken(token) && Account.Role != Role.Administrador)
            return Unauthorized(new { message = "No autorizado" });

        _accountService.RevokeToken(token, ipAddress());
        return Ok(new { message = "Token revocado" });
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult Register(RegisterRequest model)
    {
        _accountService.Register(model, Request.Headers["origin"]);
        return Ok(new { message = "Registro exitoso, revise su correo electrónico para obtener instrucciones de verificación" });
    }

    [AllowAnonymous]
    [HttpPost("verify-email")]
    public IActionResult VerifyEmail(VerifyEmailRequest model)
    {
        _accountService.VerifyEmail(model.Token);
        return Ok(new { message = "Verificación exitosa, ahora puede iniciar sesión" });
    }

    [AllowAnonymous]
    [HttpPost("forgot-password")]
    public IActionResult ForgotPassword(ForgotPasswordRequest model)
    {
        _accountService.ForgotPassword(model, Request.Headers["origin"]);
        return Ok(new { message = "Por favor revise su correo electrónico para instrucciones de restablecimiento de contraseña" });
    }

    [AllowAnonymous]
    [HttpPost("validate-reset-token")]
    public IActionResult ValidateResetToken(ValidateResetTokenRequest model)
    {
        _accountService.ValidateResetToken(model);
        return Ok(new { message = "El token es válido" });
    }

    [AllowAnonymous]
    [HttpPost("reset-password")]
    public IActionResult ResetPassword(ResetPasswordRequest model)
    {
        _accountService.ResetPassword(model);
        return Ok(new { message = "Restablecimiento de contraseña con éxito, ahora puede iniciar sesión" });
    }

    [Authorize(Role.Administrador)]
    [HttpGet]
    public ActionResult<IEnumerable<AccountResponse>> GetAll()
    {
        var accounts = _accountService.GetAll();
        return Ok(accounts);
    }

    [HttpGet("{id:int}")]
    public ActionResult<AccountResponse> GetById(int id)
    {
        // users can get their own account and admins can get any account
        if (id != Account.Id && Account.Role != Role.Administrador)
            return Unauthorized(new { message = "No autorizado" });

        var account = _accountService.GetById(id);
        return Ok(account);
    }

    [Authorize(Role.Administrador)]
    [HttpPost]
    public ActionResult<AccountResponse> Create(CreateRequest model)
    {
        var account = _accountService.Create(model);
        return Ok(account);
    }

    [HttpPut("{id:int}")]
    public ActionResult<AccountResponse> Update(int id, UpdateRequest model)
    {
        // users can update their own account and admins can update any account
        if (id != Account.Id && Account.Role != Role.Administrador)
            return Unauthorized(new { message = "No autorizado" });

        // only admins can update role
        if (Account.Role != Role.Administrador)
            model.Role = null;

        var account = _accountService.Update(id, model);
        return Ok(account);
    }

    [HttpDelete("{id:int}")]
    public IActionResult Delete(int id)
    {
        // users can delete their own account and admins can delete any account
        if (id != Account.Id && Account.Role != Role.Administrador)
            return Unauthorized(new { message = "No autorizado" });

        _accountService.Delete(id);
        return Ok(new { message = "Cuenta eliminada con éxito" });
    }

    // helper methods

    private void setTokenCookie(string token)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(7)
        };
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }

    private string ipAddress()
    {
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
            return Request.Headers["X-Forwarded-For"];
        else
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
    }
}

