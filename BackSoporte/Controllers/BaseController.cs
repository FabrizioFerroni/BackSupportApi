using BackSoporte.Entity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Principal;

namespace BackSoporte.Controllers;
[Controller]
public class BaseController : ControllerBase
{
    // returns the current authenticated account (null if not logged in)
    public Usuario Account => (Usuario)HttpContext.Items["Usuario"];
}
