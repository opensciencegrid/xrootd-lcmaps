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

extern "C" {
#include "lcmaps.h"

XrdSysMutex mutex;

int XrdSecgsiAuthzInit(const char *cfg);

char * XrdSecgsiAuthzFun(const char *pem_string, int now);
}
#define policy_count 1
static char * policy_name = "xrootd_policy";

//
// Main function
//
char *XrdSecgsiAuthzFun(const char *pem_string, int now)
{
   // Call LCMAPS from within a mutex in order to map our user.
   // If now <= 0, initialize the LCMAPS modules.
   char * name = NULL;

   // Grab the global mutex.
   XrdOucLock lock(&mutex);

   // Init the relevant fields (only once)
   if (now <= 0) {
      if (XrdSecgsiAuthzInit(pem_string) != 0) {
         return (char *)-1;
      }
      return (char *)0;
   }

   /* -1 is the mapcounter */
   // Need char, not const char.  Don't know if LCMAPS changes it.
   char * pem_string_copy = strdup(pem_string);
   uid_t uid = -1;
   gid_t * pgid_list = NULL;
   int npgid = 0;
   gid_t * sgid_list = NULL;
   int nsgid = 0;
   char *poolindex;

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
/*
   if (pgid_list)
      free(pgid_list);
   if (sgid_list)
      free(sgid_list);
   if (poolindex)
      free(poolindex);
*/
   struct passwd * pw = getpwuid(uid);
   if (pw == NULL) {
      return NULL;
   }
   name = strdup(pw->pw_name);

   return name;

}

int XrdSecgsiAuthzUsage(int rc) {
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
      {"loglevel", no_argument, NULL, 'l'},
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
      log_level;
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
   return 0;
}

