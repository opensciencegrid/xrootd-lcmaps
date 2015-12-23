/******************************************************************************/
/*                                                                            */
/*             X r d L c m a p s . c                                          */
/*                                                                            */
/* (c) 2010. Brian Bockelman, UNL                                             */
/*                                                                            */
/******************************************************************************/

/* ************************************************************************** */
/*                                                                            */
/* Authz integration for LCMAPS                                               */       
/*                                                                            */
/* ************************************************************************** */

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <dlfcn.h>

#include "XrdSys/XrdSysPthread.hh"

#include <XrdOuc/XrdOucString.hh>
#include <XrdSec/XrdSecEntity.hh>

#include "XrdVersion.hh"

XrdVERSIONINFO(XrdSecgsiAuthzFun,secgsiauthz);
XrdVERSIONINFO(XrdSecgsiAuthzKey,secgsiauthz);
XrdVERSIONINFO(XrdSecgsiAuthzInit,secgsiauthz);

extern "C"
{
#include "lcmaps_basic.h"

XrdSysMutex mutex;

int XrdSecgsiAuthzInit(const char *cfg);
int XrdSecgsiAuthzFun(XrdSecEntity &entity);
int XrdSecgsiAuthzKey(XrdSecEntity &entity, char **key);
}

#define policy_count 1
static const char policy_name [] = "xrootd_policy";
static const char plugin_name [] = "XrdSecgsiAuthz";

static const int g_certificate_format = 1;

#define PRINT(y)    std::cerr << y << "\n";

//
// Main function
//
int XrdSecgsiAuthzFun(XrdSecEntity &entity)
{
   // Call LCMAPS from within a mutex in order to map our user.

   static const char err_pfx[] = "ERROR in AuthzFun: ";
   static const char inf_pfx[] = "INFO in AuthzFun: ";

   // Grab the global mutex.
   XrdSysMutexHelper lock(&mutex);

   /* -1 is the mapcounter */
   // Need char, not const char.  Don't know if LCMAPS changes it.
   char  *pem_string_copy = strdup(entity.creds);
   char  *poolindex = NULL;
   uid_t  uid = -1;
   gid_t *pgid_list = NULL, *sgid_list = NULL;
   int    npgid = 0, nsgid = 0;

   // To manage const cast issues
   char * policy_name_copy = strdup(policy_name);

   int rc = lcmaps_run_with_pem_and_return_account(
        NULL,
        pem_string_copy,
        -1, // Map counter
        NULL,
        policy_count, // One policy
        &policy_name_copy, // Policy named "xrootd_policy"
        &uid,
        &pgid_list,
        &npgid,
        &sgid_list,
        &nsgid,
        &poolindex
   );

   free(policy_name_copy);
   free(pem_string_copy);

   if (rc) {
      PRINT(err_pfx << "LCMAPS failed or denied mapping");
      return -1;
   }
   /* // MT 2011-07-19 Why is this commented out?
   if (pgid_list)
      free(pgid_list);
   if (sgid_list)
      free(sgid_list);
   if (poolindex)
      free(poolindex);
   */
   PRINT(inf_pfx << "Got uid " << uid);
   struct passwd * pw = getpwuid(uid);
   if (pw == NULL) {
       // Fatal. Non fatal return still allows login (go figure).
      return -1;
   }

   // DN is in 'name' (--gmapopt=10), move it over to moninfo ...
   free(entity.moninfo);
   entity.moninfo = entity.name;
   // ... and copy the local username into 'name'.
   entity.name = strdup(pw->pw_name);

   PRINT(inf_pfx << "entity.name='"<< (entity.name ? entity.name : "null") << "'.");
   PRINT(inf_pfx << "entity.host='"<< (entity.host ? entity.host : "null") << "'.");
   PRINT(inf_pfx << "entity.vorg='"<< (entity.vorg ? entity.vorg : "null") << "'.");
   PRINT(inf_pfx << "entity.role='"<< (entity.role ? entity.role : "null") << "'.");
   PRINT(inf_pfx << "entity.grps='"<< (entity.grps ? entity.grps : "null") << "'.");
   PRINT(inf_pfx << "entity.endorsements='"<< (entity.endorsements ? entity.endorsements : "null") << "'.");
   PRINT(inf_pfx << "entity.moninfo='"<< (entity.moninfo ? entity.moninfo : "null") << "'.");

   // That means OK
   return 0;
}

//
// AuthzKey -- copy from xrootd/src/XrdSecgsi/XrdSecgsiAuthzFunDN.cc
//
int XrdSecgsiAuthzKey(XrdSecEntity &entity, char **key)
{
   // Implementation of XrdSecgsiAuthzKey extracting the information from the
   // proxy chain in entity.creds

   static const char* err_pfx = "ERROR in AuthzKey: ";
   static const char* inf_pfx = "INFO in AuthzKey: ";

   // Must have got something
   if (!key) {
      PRINT(err_pfx << "'key' must be defined.");
      return -1;
   }
   if (!entity.name) {
      PRINT(err_pfx << "'entity.name' must be defined (-gmapopt=10).");
      return -1;
   }

   // PRINT(inf_pfx << "entity.name='"<< (entity.name ? entity.name : "null") << "'.");
   // PRINT(inf_pfx << "entity.vorg='"<< (entity.vorg ? entity.vorg : "null") << "'.");
   // PRINT(inf_pfx << "entity.role='"<< (entity.role ? entity.role : "null") << "'.");
   // PRINT(inf_pfx << "entity.endorsements='"<< (entity.endorsements ? entity.endorsements : "null") << "'.");

   // Return DN (in name) + endrosments as the key:
   XrdOucString s(entity.name);
   if (entity.endorsements) {
     s += "::";
     s += entity.endorsements;
   }
   *key = strdup(s.c_str());
   PRINT(inf_pfx << "Returning '" << s << "' of length " << s.length() << " as key.");
   return s.length() + 1;

   // To use the whole proxy as the key:
   // *key = new char[entity.credslen + 1];
   // strcpy(*key, entity.creds);
   // PRINT(inf_pfx << "Returning creds of len " << entity.credslen << " as key.");
   // return entity.credslen;
}

int XrdSecgsiAuthzUsage(int rc)
{
   std::cerr << "Usage: --lcmapscfg <filename> [--loglevel <level>] [--osg]" << std::endl
             << "    --loglevel   passed on as LCMAPS_DEBUG_LEVEL" << std::endl
             << "    --osg        currently ignored" << std::endl;
   return rc;
}

//
// Init the relevant parameters from a dedicated config file
//
int XrdSecgsiAuthzInit(const char *cfg)
{
   static const char err_pfx[] = "ERROR in XrdSecgsiAuthzInit: ";
   static const char inf_pfx[] = "INFO in XrdSecgsiAuthzInit: ";

   // Return 0 on success, -1 otherwise
   int osg = 0;
   std::string cfg_file  = "/etc/xrootd/lcmaps.cfg";
   std::string log_level = "3";

   // Reload LCMAPS with 
   if (dlopen("liblcmaps.so", RTLD_LAZY|RTLD_GLOBAL) == 0) {
      PRINT(err_pfx << "Unable to reload LCMAPS library! dlopen error: " << dlerror());
      return -1;
   }

   // Convert the input string into the typical argc/argv pair
   if (cfg) {
      char * cfg_copy = strdup(cfg);
      int argc = 0;
      char * token = 0;
      while ((token = strsep(&cfg_copy, ",")) != 0) {
         argc++;
      }
      free(cfg_copy);
      char **argv = (char **) calloc(sizeof(char *), argc + 1);
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
      for (int i=0; i<argc+1; i++) {
          free(argv[i]);
      }
      free(argv);
   }

   setenv("LCMAPS_DB_FILE",     cfg_file.c_str(),  1);
   setenv("LCMAPS_VERIFY_TYPE", "uid_pgid",        1);
   setenv("LCMAPS_DEBUG_LEVEL", log_level.c_str(), 0);

/*  This function is not currently exposed out to the world.
   if (osg != 0) {
      lcmaps_disable_voms_attributes_verification();
   }
*/

   FILE *fp = fdopen(2, "w");
   if (lcmaps_init_and_log(fp, 1)) {
      PRINT(err_pfx << "Failed to initialize LCMAPS");
      return -1;
   }

   // Done
   // 1 means 'OK and I want the certificate in PEM base64 format'
   return g_certificate_format;
}
