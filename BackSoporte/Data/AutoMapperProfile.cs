using AutoMapper;
using BackSoporte.Entity;
using BackSoporte.Models.Accounts;
using System.Security.Principal;

namespace BackSoporte.Data
{
    public class AutoMapperProfile: Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<Usuario, AccountResponse>();

            CreateMap<Usuario, AuthenticateResponse>();

            CreateMap<RegisterRequest, Usuario>();

            CreateMap<CreateRequest, Usuario>();

            CreateMap<UpdateRequest, Usuario>()
                .ForAllMembers(x => x.Condition(
                    (src, dest, prop) =>
                    {
                        // ignore null & empty string properties
                        if (prop == null) return false;
                        if (prop.GetType() == typeof(string) && string.IsNullOrEmpty((string)prop)) return false;

                        // ignore null role
                        if (x.DestinationMember.Name == "Role" && src.Role == null) return false;

                        return true;
                    }
                ));
        }
    }
}
