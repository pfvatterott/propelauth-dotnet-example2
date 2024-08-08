using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

var rsa = RSA.Create();
rsa.ImportFromPem(@"-----BEGIN PUBLIC KEY-----

-----END PUBLIC KEY-----
");

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateAudience = false,
        ValidAlgorithms = new List<string>() { "RS256" },
        ValidIssuer = "https://38291285.propelauthtest.com",
        IssuerSigningKey = new RsaSecurityKey(rsa),
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireLogin", policy => policy.Requirements.Add(new RequiredAuthentication()));
    options.AddPolicy("RequireCanViewBillingPermission", policy => policy.Requirements.Add(new RequirePermission("org_id", "can_view_billing")));
    options.AddPolicy("RequireOrgMembership", policy => policy.Requirements.Add(new RequiredOrgMembership("org_id")));
    options.AddPolicy("RequireOwnerRole", policy => policy.Requirements.Add(new RequireRole("org_id", "Owner")));
    options.AddPolicy("RequireAdminRole", policy => policy.Requirements.Add(new RequireRole("org_id", "Admin")));
});

builder.Services.AddSingleton<IAuthorizationHandler, RequiredAuthenticationHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, RequirePermissionHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, RequiredOrgMembershipHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, RequireRoleHandler>();
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseHttpsRedirection();

app.MapGet("/", async (ClaimsPrincipal user) =>
{
    var userId = user.FindFirst("user_id");
    return "Hello user with ID " + userId;
})
.RequireAuthorization("RequireLogin");



app.MapGet("/api/org/{orgId}", async (ClaimsPrincipal user, string orgId) =>
{
    return $"Hello user with ID {user.FindFirst("user_id")} from org {orgId}";
})
.RequireAuthorization("RequireCanViewBillingPermission");

// app.MapGet("/api/org/{orgId}", async (ClaimsPrincipal user, string orgId) =>
// {
//     var client = new HttpClient();
//     string apiUrl = "https://38291285.propelauthtest.com/api/backend/v1/user/7095f9df-08ae-4f7f-98ea-464eb438cad5";
//     var jsonPayload = new
//         {
//             username = "alkansldkfjo123ia",
//             first_name = "firstname",
//             last_name = "lastname",
//             properties = new Dictionary<string, string> { { "favoriteSport", "value123" } },
//             metadata = new Dictionary<string, string> { { "test", "test123" } }
//         };
//     var content = new StringContent(System.Text.Json.JsonSerializer.Serialize(jsonPayload));
//     content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
//     client.DefaultRequestHeaders.Add("Authorization", "Bearer 6497c187318fa11cc82368b1abbd8d3175bab976a119a8d099fdf5b7e4fa05b9ae305edf5495e7aaa04bd1fd96fda707");
//     HttpResponseMessage response = await client.PutAsync(apiUrl, content);
//     if (response.IsSuccessStatusCode)
//         {
//             Console.WriteLine("Request successful!");
//             // You can handle the response content here if needed
//         }
//         else
//         {
//             Console.WriteLine($"Error: {response.StatusCode}");
//         }

//     return $"Hello user with ID {user.FindFirst("user_id")} from org {orgId}";
// })
// // .RequireAuthorization("RequireLogin")
// // .RequireAuthorization("RequireCanViewBilling");
// // .RequireAuthorization("RequireOrgMembership");
// .RequireAuthorization("RequireRole", "Admin");


app.Run();

public class RequiredAuthenticationHandler : AuthorizationHandler<RequiredAuthentication>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        RequiredAuthentication requirement)
    {
        var userId = context.User.FindFirst("user_id");
        if (userId != null)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}

public class RequireRoleHandler : AuthorizationHandler<RequireRole>
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public RequireRoleHandler(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
       RequireRole requirement)
    {
        var routeValues = _httpContextAccessor.HttpContext.GetRouteData().Values;
        var orgId = routeValues["orgId"]?.ToString();
        var orgsClaim = context.User.FindFirst("org_id_to_org_member_info");
        if (orgsClaim != null)
        {
            var orgs = JsonConvert.DeserializeObject<Dictionary<string, OrgMemberInfo>>(orgsClaim.Value);
            var targetOrg = orgs.FirstOrDefault(o => o.Key == orgId);
            if (targetOrg.Value != null)
            {
                var userRole = targetOrg.Value.user_role;
                if (userRole != null && requirement.Role.Contains(userRole))
                {
                    context.Succeed(requirement);
                }
            }
        }
        return Task.CompletedTask;
    }
}

public class RequiredOrgMembershipHandler : AuthorizationHandler<RequiredOrgMembership>
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public RequiredOrgMembershipHandler(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
       RequiredOrgMembership requirement)
    {
        var routeValues = _httpContextAccessor.HttpContext.GetRouteData().Values;
        var orgId = routeValues["orgId"]?.ToString();
        var orgsClaim = context.User.FindFirst("org_id_to_org_member_info");

        if (orgsClaim != null)
        {
            var orgs = JsonConvert.DeserializeObject<Dictionary<string, OrgMemberInfo>>(orgsClaim.Value);
            var targetOrg = orgs.FirstOrDefault(o => o.Key == orgId);
            if (targetOrg.Value != null)
            {
                context.Succeed(requirement);
            }
        }
        return Task.CompletedTask;
    }
}

public class RequirePermissionHandler : AuthorizationHandler<RequirePermission>
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public RequirePermissionHandler(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
       RequirePermission requirement)

    {
        var routeValues = _httpContextAccessor.HttpContext.GetRouteData().Values;
        var orgId = routeValues["orgId"]?.ToString();
        var orgsClaim = context.User.FindFirst("org_id_to_org_member_info");
        if (orgsClaim != null)
        {
            var orgs = JsonConvert.DeserializeObject<Dictionary<string, OrgMemberInfo>>(orgsClaim.Value);
            var targetOrg = orgs.FirstOrDefault(o => o.Key == orgId);
            if (targetOrg.Value != null)
            {
                if (targetOrg.Value.user_permissions.Contains(requirement.Permission))
                {
                    context.Succeed(requirement);
                }
            }
        }
        return Task.CompletedTask;
    }
}

public class OrgMemberInfo
{
    public string org_id { get; set; }
    public string org_name { get; set; }
    public string url_safe_org_name { get; set; }
    public Dictionary<string, object> org_metadata { get; set; }
    public string user_role { get; set; }
    public List<string> inherited_user_roles_plus_current_role { get; set; }
    public string org_role_structure { get; set; }
    public List<string> additional_roles { get; set; }
    public List<string> user_permissions { get; set; }
}

public class RequiredAuthentication : IAuthorizationRequirement
{
}

public class RequirePermission : IAuthorizationRequirement
{
    public string OrgId { get; }
    public string Permission { get; }

    public RequirePermission(string orgId, string permission)
    {
        OrgId = orgId;
        Permission = permission;
    }
}

public class RequiredOrgMembership : IAuthorizationRequirement
{
    public string OrgId { get; }

    public RequiredOrgMembership(string orgId)
    {
        OrgId = orgId;
    }
}

public class RequireRole : IAuthorizationRequirement
{
    public string OrgId { get; }
    public string Role { get; }

    public RequireRole(string orgId, string role)
    {
        OrgId = orgId;
        Role = role;
    }
}


