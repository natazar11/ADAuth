using System.DirectoryServices.AccountManagement;
using Microsoft.Extensions.Configuration;

public class ADAuthentication
{
    private readonly string domainName;
    private readonly string ldapPath;

    public ADAuthentication(IConfiguration config)
    {
        domainName = config["ActiveDirectory:DomainName"];
        ldapPath = config["ActiveDirectory:LdapPath"];
    }

    public bool Authenticate(string username, string password)
    {
        try
        {
            using (var context = new PrincipalContext(ContextType.Domain, domainName))
            {
                return context.ValidateCredentials(username, password);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during authentication: {ex.Message}");
            return false;
        }
    }
}
