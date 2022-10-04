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
}

