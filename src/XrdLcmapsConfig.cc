
#include <dlfcn.h>
#include <string.h>
#include <getopt.h>

#include <iostream>

extern "C" {
#include <lcmaps.h>
}

static const char plugin_name [] = "XrdSecgsiAuthz";
static const char default_db  [] = "/etc/lcmaps.db";
static const char default_policy_name [] = "xrootd_policy";

#define PRINT(y)    std::cerr << y << "\n";

int XrdSecgsiAuthzUsage(int rc)
{
   std::cerr << "Usage: --lcmapscfg <filename> [--loglevel <level>]" << std::endl
             << "    --loglevel   passed on as LCMAPS_DEBUG_LEVEL" << std::endl;
   return rc;
}

int XrdSecgsiAuthzConfig(const char *cfg)
{
   static const char err_pfx[] = "ERROR in xrootd-lcmaps config: ";
   static const char inf_pfx[] = "INFO in xrootd-lcmaps config: ";

   // Return 0 on success, -1 otherwise
   const char *cfg_file  = default_db;
   const char *policy_name = default_policy_name;
   char *log_level = 0;

   // Reload LCMAPS with 
   if (dlopen("liblcmaps.so", RTLD_LAZY|RTLD_GLOBAL) == 0) {
      PRINT(err_pfx << "Unable to reload LCMAPS library! dlopen error: " << dlerror());
      return -1;
   }

   char **argv = NULL;
   int argc = 0;

   // Convert the input string into the typical argc/argv pair
   if (cfg) {
      char * cfg_copy = strdup(cfg);
      char * token = 0;
      while ((token = strsep(&cfg_copy, ",")) != 0) {
         argc++;
      }
      free(cfg_copy);
      argv = (char **) calloc(sizeof(char *), argc + 2);
      cfg_copy = strdup(cfg);
      argc = 0;
      argv[argc++] = strdup(plugin_name);
      while ((token = strsep(&cfg_copy, ",")) != 0) {
         argv[argc++] = strdup(token);
      }
      free(cfg_copy);

      if (argc < 3) {
         return XrdSecgsiAuthzUsage(-1);
      }

      // Use getopt to parse the appropriate options
      char c;
      int osg;  // Ignored in current versions.
      static struct option long_options[] = {
         {"osg",       no_argument, &osg, 1},
         {"lcmapscfg", required_argument, 0, 'c'},
         {"loglevel",  required_argument, 0, 'l'},
         {"policy",    required_argument, 0, 'p'},
         {0, 0, 0, 0}
      };
      int option_index = 0;
      while ((c = getopt_long(argc, argv, "c:l:p:", long_options, &option_index)) != -1) {
         switch(c) {
            case 0:
                     // A flag was parsed ...
                     break;
            case 'c':
                     if (optarg != 0) {
                        cfg_file = optarg;
                        PRINT(inf_pfx << "XrdLcmaps: Setting LCMAPS config file to " << cfg_file << ".");
                     }
                     break;
            case 'l':
                     if (optarg != 0) {
                        log_level = optarg;
                        PRINT(inf_pfx << "XrdLcmaps: Setting LCMAPS log level to " << log_level << ".");
                     }
                     break;
            case 'p':
                     if (optarg != 0) {
                        policy_name = optarg;
                        PRINT(inf_pfx << "XrdLcmaps: Using LCMAPS policy name " << policy_name << ".");
                     }
            case '?':
                     return XrdSecgsiAuthzUsage(-1);
            default:
                     PRINT(err_pfx << "XrdLcmaps: unexpected return value from getopt_long: '" << c << "'.");
                     return -1;
         }
      }
   }

   setenv("LCMAPS_DB_FILE", cfg_file, 1);
   setenv("LCMAPS_POLICY_NAME", policy_name, 1);

   setenv("LCMAPS_VERIFY_TYPE", "uid_pgid", 1);
   if (log_level == 0) {
      setenv("LCMAPS_DEBUG_LEVEL", "3", 0);
   } else {
      setenv("LCMAPS_DEBUG_LEVEL", log_level, 0);
   }

   FILE *fp = fdopen(2, "w");
   if (lcmaps_init_and_log(fp, 1)) {
      PRINT(err_pfx << "Failed to initialize LCMAPS");
      return -1;
   }

   if (argv != NULL) {
      for (int i=0; i<argc+1; i++) {
         free(argv[i]);
      }
      free(argv);
   }

   return 0;
}
