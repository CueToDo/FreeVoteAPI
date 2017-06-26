using System;
using System.Text;
using System.Collections.Generic;

using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

using DNSD.Data.OneVoice;
using DNSD.Data.OneVoice.Interfaces;

using DNSD.Web.API;

using FreeVoteAPI.Classes;


namespace FreeVoteAPI.Controllers
{
    [Route("authentication")]
    public class AuthenticationController : Controller
    {
        //static stuff
        private static JwtSecurityTokenHandler JwtHandler = new JwtSecurityTokenHandler();
        private const string secret = "This is my shared, not so secret, secret!";
        private static SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        private static SigningCredentials signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
        private static string JWTIssuer = "https://free.vote";
        private static string JWTAudience = "https://free.vote";
        private static TokenValidationParameters tokenValidationParameters = new TokenValidationParameters()
        {
            ValidIssuers = new string[] { JWTIssuer },
            ValidAudiences = new string[] { JWTAudience },
            IssuerSigningKey = securityKey
        };

        // GET api/values
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }

        protected VoterIDData dwAuthUser = Factory.VoterIdentification();

        //http://stackoverflow.com/questions/23412021/defaultinlineconstraintresolver-error-in-webapi-2 no "string" constraint
        [Route("signin")]
        [HttpPost]
        public string SignIn([FromBody] string website, [FromBody] string email, [FromBody] string password)
        {
            string IPAddress = DNC.Web.Request.RequestIP(HttpContext);

            DNSD.Data.OneVoice.Interfaces.SignInResult WebSIR = dwAuthUser.SignInOrSignUp(website, email, password, IPAddress, Config.MaxSignInAttempts, Config.MaxRegistrationsPerHour, Config.UnauthorisedActivityWindowInHours);

            if (WebSIR.SignInResult == SignInResultsEnum.SignInSuccess)
            {
                //ToDo get roles
                List<string> roles = new List<string> { "user" };
                return JWTSuccess(website, email, WebSIR.VoterID, WebSIR.SessionID, roles);
            }
            else
            {
                return JWTFail(WebSIR.SignInResult, WebSIR.AttemptsRemaining);
            }
        }

        private string JWT(List<Claim> claims)
        {

            var claimsIdentity = new ClaimsIdentity(claims, "Custom");

            var securityTokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = claimsIdentity,
                Issuer = JWTIssuer,
                Audience = JWTAudience,
                SigningCredentials = signingCredentials
            };

            SecurityToken plainToken = JwtHandler.CreateToken(securityTokenDescriptor);
            string signedAndEncodedToken = JwtHandler.WriteToken(plainToken);

            return signedAndEncodedToken;
        }

        private string JWTSuccess(string website, string email, int voterID, int sessionID, List<string> roles)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim("SignInResult", SignInResultsEnum.SignInSuccess.ToString()),
                new Claim("Website", website),
                new Claim(ClaimTypes.Email, email),
                new Claim("VoterID", voterID.ToString()),
                new Claim("SessionID", sessionID.ToString())
            };

            foreach (string role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            return JWT(claims);
        }

        private string JWTFail(SignInResultsEnum signInResult, int attemptsRemaining)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim("SignInResult", signInResult.ToString()),
                new Claim("SignAttemptsRemaining", attemptsRemaining.ToString())
            };

            return JWT(claims);
        }



        private SecurityToken ValidatedJWT(string signedAndEncodedToken)
        {
            SecurityToken validatedToken;
            JwtHandler.ValidateToken(signedAndEncodedToken, tokenValidationParameters, out validatedToken);
            return validatedToken;
        }

    }
}
