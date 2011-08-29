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
#include "XrdOuc/XrdOucLock.hh"

#include <XrdCrypto/XrdCryptosslAux.hh>
#include <XrdCrypto/XrdCryptosslgsiAux.hh>
#include <XrdCrypto/XrdCryptoX509.hh>
#include <XrdCrypto/XrdCryptoX509Chain.hh>
#include <XrdOuc/XrdOucString.hh>
#include <XrdSec/XrdSecEntity.hh>
#include <XrdSecgsi/XrdSecgsiTrace.hh>
#include <XrdSut/XrdSutBucket.hh>

extern "C"
{
#include "lcmaps.h"

XrdSysMutex mutex;

int XrdSecgsiAuthzInit(const char *cfg);
int XrdSecgsiAuthzFun(XrdSecEntity &entity);
int XrdSecgsiAuthzKey(XrdSecEntity &entity, char **key);
}

#define policy_count 1
static char * policy_name = "xrootd_policy";

static const int g_certificate_format = 1;

#undef  PRINT
#define PRINT(y)    std::cerr << y << "\n";

//
// Main function
//
int XrdSecgsiAuthzFun(XrdSecEntity &entity)
{
   // Call LCMAPS from within a mutex in order to map our user.

   static const char* err_pfx = "ERROR in AuthzFun: ";
   static const char* inf_pfx = "INFO in AuthzFun: ";

   // Grab the global mutex.
   XrdOucLock lock(&mutex);

   /* -1 is the mapcounter */
   // Need char, not const char.  Don't know if LCMAPS changes it.
   char  *pem_string_copy = strdup(entity.creds);
   char  *poolindex = NULL;
   uid_t  uid = -1;
   gid_t *pgid_list = NULL, *sgid_list = NULL;
   int    npgid = 0, nsgid = 0;

   int rc = lcmaps_run_with_pem_and_return_account(
        NULL,
        pem_string_copy,
        -1, // Map counter
        NULL,
        policy_count, // One policy
        &policy_name, // Policy named "xrootd_policy"
        &uid,
        &pgid_list,
        &npgid,
        &sgid_list,
        &nsgid,
        &poolindex
   );
   free(pem_string_copy);
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

   // DN is in 'name' (--gmapopt=10), move it over to grps ...
   free(entity.grps);
   entity.grps = entity.name;
   // ... and copy the local username into 'name'.
   entity.name = strdup(pw->pw_name);

   PRINT(inf_pfx << "entity.name='"<< (entity.name ? entity.name : "null") << "'.");
   PRINT(inf_pfx << "entity.host='"<< (entity.host ? entity.host : "null") << "'.");
   PRINT(inf_pfx << "entity.vorg='"<< (entity.vorg ? entity.vorg : "null") << "'.");
   PRINT(inf_pfx << "entity.role='"<< (entity.role ? entity.role : "null") << "'.");
   PRINT(inf_pfx << "entity.grps='"<< (entity.grps ? entity.grps : "null") << "'.");
   PRINT(inf_pfx << "entity.endorsements='"<< (entity.endorsements ? entity.endorsements : "null") << "'.");

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
   std::cerr << "Usage: --lcmapscfg <filename> [--osg]" << std::endl;
   return rc;
}

//
// Init the relevant parameters from a dedicated config file
//
int XrdSecgsiAuthzInit(const char *cfg)
{
   // Return 0 on success, -1 otherwise
   int i, osg = 0;
   char * cfg_file;
   char * log_level = NULL;

   // Reload LCMAPS with 
   //if (dlopen("liblcmaps.so", RTLD_NOLOAD | RTLD_GLOBAL) == NULL) {
   //   std::cerr << "Unable to reload LCMAPS library!" << std::endl;
      //return -1;
   //}

   // Convert the input string into the typical argc/argv pair
   char * cfg_copy = strdup(cfg);
   int argc = 0;
   char * token = NULL;
   while ((token = strsep(&cfg_copy, ",")) != NULL) {
      argc ++;
   }
   free(cfg_copy);
   argc = 0;
   char **argv = (char **)calloc(sizeof(char *), argc+2);
   cfg_copy = strdup(cfg);
   argv[0] = "XrdSecgsiAuthz";
   while ((token = strsep(&cfg_copy, ",")) != NULL) {
      argc ++;
      argv[argc] = strdup(token);
   }
   free(cfg_copy);

   if (argc < 3) {
      return XrdSecgsiAuthzUsage(-1);
   }

   // Use getopt to parse the appropriate options
   char c;
   static struct option long_options[] = {
      {"osg", no_argument, &osg, 1},
      {"lcmapscfg", required_argument, NULL, 'c'},
      {"loglevel", optional_argument, NULL, 'l'},
      {0, 0, 0, 0}
   };
   int option_index;
   while ((c = getopt_long(argc, argv, "c:l:", long_options, &option_index)) != -1) {
      switch(c) {
         case 'c':
                  if (optarg != NULL)
                     cfg_file = optarg;
                  break;
         case 'l':
                  if (optarg != NULL)
                     log_level = optarg;
                  break;
         default:
                  XrdSecgsiAuthzUsage(-1);
      }
   }

   setenv("LCMAPS_DB_FILE", cfg_file, 1);

   setenv("LCMAPS_VERIFY_TYPE", "uid_pgid", 1);
   if (log_level == NULL) {
      setenv("LCMAPS_DEBUG_LEVEL", "0", 0);
   } else {
      setenv("LCMAPS_DEBUG_LEVEL", log_level, 0);
      free(log_level);
   }

/*  This function is not currently exposed out to the world.
   if (osg != 0) {
      lcmaps_disable_voms_attributes_verification();
   }
*/

   if (lcmaps_init(0)) { // Sends the logs to syslog.
      return -1;
   }

   // Done
   // 1 means 'OK and I want the certificate in PEM base64 format'
   return g_certificate_format;
}
