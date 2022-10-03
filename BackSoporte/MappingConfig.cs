using AutoMapper;
using BackSoporte.Entity;
using BackSoporte.Models.Accounts;

namespace BackSoporte
{
    public class MappingConfig
    {
        public static MapperConfiguration RegisterMaps()
        {
            var mappingConfig = new MapperConfiguration(config =>
            {
                config.CreateMap<Usuario, AccountResponse>();

                config.CreateMap<Usuario, AuthenticateResponse>();

                config.CreateMap<RegisterRequest, Usuario>();

                config.CreateMap<CreateRequest, Usuario>();

                config.CreateMap<UpdateRequest, Usuario>()
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
            });

            return mappingConfig;
        }
    }
}
