using System.IO;
using Microsoft.Extensions.Configuration;

using DNSD.Functions;

namespace FreeVoteAPI.Classes
{
    public static class Config
    {
        private static IConfigurationRoot configuration { get; set; }

        public static IConfigurationRoot Configuration
        {
            get
            {
                if (configuration == null)
                {
                    var builder = new ConfigurationBuilder()
                        .SetBasePath(Directory.GetCurrentDirectory())
                        .AddJsonFile("appsettings.json");

                    configuration = builder.Build();
                }
                return configuration;
            }
        }

        public static int MaxSignInAttempts { get { return Configuration["MaxSignInAttempts"].ToInt(); } }
        public static int MaxRegistrationsPerHour { get { return Configuration["MaxRegistrationsPerHour"].ToInt(); } }
        public static int UnauthorisedActivityWindowInHours { get { return Configuration["UnauthorisedActivityWindowInHours"].ToInt(); } }

    }
}