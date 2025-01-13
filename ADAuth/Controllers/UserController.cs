using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;

namespace ADAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private static readonly string ldapPath = "LDAP://kouzi.lb";
        private static readonly string DomainName = "kouzi.lb";
        private static readonly string adminUsername = "MenaMe";
        private static readonly string adminPassword = "MenaP@ssw0rd";


        //CREATE USER
        [HttpPost("createuser")]
        public IActionResult CreateUser([FromBody] UserModel user)
        {
            try
            {
                CreateUserInAD(user);
                return Ok("User created successfully.");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error creating user: {ex.Message}");
            }
        }

        private void CreateUserInAD(UserModel user)
        {
            try
            {
                using (var entry = new DirectoryEntry(ldapPath, adminUsername, adminPassword))
                {
                    var newUser = entry.Children.Add($"CN={user.UserName},CN=Users", "user");
                    newUser.Properties["sAMAccountName"].Value = user.UserName;
                    newUser.Properties["userPrincipalName"].Value = $"{user.UserName}@kouzi.lb";
                    newUser.Properties["givenName"].Value = user.FirstName;
                    newUser.Properties["sn"].Value = user.LastName;

                    newUser.CommitChanges();
                    newUser.Invoke("SetPassword", user.Password);

                    int val = (int)newUser.Properties["userAccountControl"].Value;
                    newUser.Properties["userAccountControl"].Value = val & ~0x2;

                    val = (int)newUser.Properties["userAccountControl"].Value;

                    newUser.Properties["userAccountControl"].Value = val | 0x10000;

                    newUser.CommitChanges();
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error in creating user: {ex.Message}");
            }
        }




        //GET USERS FROM GRP
        [HttpGet("usersfromgroup/{groupName}")]
        public IActionResult GetUsersFromGroup(string groupName)
        {
            try
            {
                List<string> users = RetrieveUsersFromGroup(groupName);

                if (users.Count > 0)
                {
                    return Ok(users);
                }
                else
                {
                    return NotFound($"No users found in group {groupName}");
                }
            }
            catch (Exception ex)
            {
                return BadRequest($"Error retrieving users: {ex.Message}");
            }
        }

        private List<string> RetrieveUsersFromGroup(string groupName)
        {
            List<string> users = new List<string>();

            try
            {
                using (var entry = new DirectoryEntry(ldapPath, adminUsername, adminPassword))
                {
                    DirectorySearcher searcher = new DirectorySearcher(entry)
                    {
                        Filter = $"(&(objectClass=group)(CN={groupName}))",
                        PropertiesToLoad = { "member" }
                    };

                    SearchResult result = searcher.FindOne();

                    if (result != null)
                    {
                        foreach (var member in result.Properties["member"])
                        {
                            users.Add(member.ToString());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error retrieving users from group: {ex.Message}");
            }

            return users;
        }

        //CHANGE PASSWORD
        [HttpPost("changepassword")]
        public IActionResult ChangePassword([FromBody] PasswordChangeModel passwordChange)
        {
            try
            {
                if (ValidateUser(passwordChange.UserName, passwordChange.OldPassword))
                {
                    bool passwordChanged = ChangeUserPassword(passwordChange.UserName, passwordChange.NewPassword);
                    if (passwordChanged)
                    {
                        return Ok("Password changed successfully.");
                    }
                    else
                    {
                        return BadRequest("Error changing password.");
                    }
                }
                else
                {
                    return BadRequest("Old password is incorrect.");
                }
            }
            catch (Exception ex)
            {
                return BadRequest($"Error changing password: {ex.Message}");
            }
        }


        public static bool ChangeUserPassword(string username, string newPassword)
        {
            try
            {
                string ldapP = $"{ldapPath}/CN={username},CN=Users,DC=kouzi,DC=lb";

                using (DirectoryEntry userEntry = new DirectoryEntry(ldapP, adminUsername, adminPassword))
                {
                    userEntry.Invoke("SetPassword", new object[] { newPassword });

                    userEntry.CommitChanges();
                    Console.WriteLine("Password changed successfully.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error changing password: {ex.Message}, StackTrace: {ex.StackTrace}");
                return false;
            }
        }



        public static bool ValidateUser(string username, string password)
        {
            using (var context = new PrincipalContext(ContextType.Domain, DomainName))
            {
                return context.ValidateCredentials(username, password);
            }
        }

    }

    //MODELS
    public class UserModel
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
    }
    public class PasswordChangeModel
    {
        public string UserName { get; set; }
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
    }
}
