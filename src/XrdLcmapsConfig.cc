
#include <dlfcn.h>
#include <string.h>
#include <getopt.h>

#include <iostream>
#include <sstream>
#include <mutex>

extern "C" {
#include <lcmaps.h>
}

// Disable LCMAPS completely
int g_no_authz = 0;

static const char plugin_name [] = "XrdSecgsiAuthz";
static const char default_db  [] = "/etc/lcmaps.db";
static const char default_policy_name [] = "xrootd_policy";
static const char default_log_level [] = "3";

#define PRINT(y)    std::cerr << y << "\n";

namespace {

int XrdSecgsiAuthzUsage(int rc)
{
   std::cerr << "Usage: [--lcmapscfg <filename>] [--loglevel <level>] [--no-authz] [--policy <lcmaps_policy>]" << std::endl
             << "    --loglevel   passed on as LCMAPS_DEBUG_LEVEL" << std::endl
             << "    --policy     passed on as LCMAPS_POLICY_NAME" << std::endl;
   return rc;
}

int UsageNew(int rc)
{
    std::cerr << "Usage: Provide zero-or-more comma-separated configuration directives." << std::endl
              << "      lcmapscfg=<filename>   : Location of the lcmaps configuration file (default: " << default_db << ")" << std::endl
              << "      loglevel=<level>       : LCMAPS log level (default: 3)" << std::endl
              << "      no-authz               : Skip LCMAPS callout" << std::endl
              << "      policy=<lcmaps_policy> : LCMAPS policy to use (default: " << default_policy_name << ")" << std::endl
              << "Example: lcmapscfg=/etc/xrootd/lcmaps.cfg,policy=authorize_only" << std::endl;
    return rc;
}

}


int XrdSecgsiAuthzConfig(const char *cfg)
{
   static const char err_pfx[] = "ERROR in xrootd-lcmaps config: ";
   static const char inf_pfx[] = "INFO in xrootd-lcmaps config: ";
   static const char warn_pfx[] = "WARNING in xrootd-lcmaps config: ";

   // Return 0 on success, -1 otherwise
   std::string cfg_file  = default_db;
   std::string policy_name = default_policy_name;
   std::string log_level;

   // Reload LCMAPS with 
   if (dlopen("liblcmaps.so", RTLD_LAZY|RTLD_GLOBAL) == 0) {
      PRINT(err_pfx << "Unable to reload LCMAPS library! dlopen error: " << dlerror());
      return -1;
   }

   char **argv = NULL;
   int argc = 0;

   // Convert the input string into the typical argc/argv pair
   if (cfg && cfg[0] == '-') {
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

      // Use getopt to parse the appropriate options
      char c;
      int osg;  // Ignored in current versions.
      static struct option long_options[] = {
         {"osg",       no_argument, &osg, 1},
         {"lcmapscfg", required_argument, 0, 'c'},
         {"loglevel",  required_argument, 0, 'l'},
         {"policy",    required_argument, 0, 'p'},
         {"no-authz",  no_argument, &g_no_authz, 1},
         {0, 0, 0, 0}
      };
      int option_index = 0;
      bool invalid_arg = false;
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
                     break;
            case '?':
                     XrdSecgsiAuthzUsage(-1);
                     invalid_arg = true;
            default:
                     PRINT(err_pfx << "XrdLcmaps: unexpected return value from getopt_long: '" << c << "'.");
                     invalid_arg = true;
         }
      }
      if (invalid_arg) {return -1;}
   } else if (cfg) {
      // In this case, tokenize according to the new rules
      std::stringstream ss(cfg);
      std::string item;
      while (std::getline(ss, item, ',')) {
          auto offset = item.find("=");
          if (offset == std::string::npos) {
              // Flags
              if (item == "no-authz") {
                  g_no_authz = 1;
              } else {
                  std::cerr << "Unknown configuration directive: " << item << std::endl;
                  return UsageNew(-1);
              }
          } else {
              auto key = item.substr(0, offset);
              auto value = item.substr(offset+1);
              if (key == "lcmapscfg") {
                  cfg_file = value;
                  if (g_no_authz) {
		    PRINT(warn_pfx << "Setting LCMAPS config file" << cfg_file << " won't be used, no-authz option is set.");
		  }
		  else{
		    PRINT(inf_pfx << "XrdLcmaps: Setting LCMAPS config file to " << cfg_file << ".");
		  }

              } else if (key == "policy") {
                  policy_name = value;
                  if (g_no_authz) {
		    PRINT(warn_pfx << "Setting LCMAPS policy name " << policy_name << " won't be used, no-authz option is set.");
                  }
		  else{
		    PRINT(inf_pfx << "XrdLcmaps: Using LCMAPS policy name " << policy_name << ".");
		  }
              } else if (key == "loglevel") {
                  log_level = value;
		  if (g_no_authz) {
		    PRINT(warn_pfx << "Setting LCMAPS log level " << log_level << " won't be used, no-authz option is set.");
                  }
		  else{
		    PRINT(inf_pfx << "XrdLcmaps: Using LCMAPS policy name " << policy_name << ".");
		  }
              } else {
                  std::cerr << "Unknown configuration directive: " << item << std::endl;
                  return UsageNew(-1);
              }
          }
      }
   }

   setenv("LCMAPS_DB_FILE", cfg_file.c_str(), 0);
   setenv("LCMAPS_POLICY_NAME", policy_name.c_str(), 0);

   setenv("LCMAPS_VERIFY_TYPE", "uid_pgid", 1);
   setenv("LCMAPS_DEBUG_LEVEL", log_level.c_str(), 0);

   if (!g_no_authz) {
      FILE *fp = fdopen(2, "w");
      if (lcmaps_init_and_log(fp, 1)) {
         PRINT(err_pfx << "Failed to initialize LCMAPS");
         return -1;
      }
   }
   else {
     PRINT(inf_pfx << " LCMAPS: no-authz option is set; LCMAPS will not be invoked");
   }


   if (argv != NULL) {
      for (int i=0; i<argc+1; i++) {
         free(argv[i]);
      }
      free(argv);
   }

   return 0;
}

// lcmaps is not thread safe
// Access is shared between XrdLcmaps and XrdHttpLcmaps
std::mutex g_lcmaps_mutex;
