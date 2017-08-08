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

#include "XrdLcmapsConfig.hh"
#include "XrdLcmapsKey.hh"
#include "GlobusSupport.hh"

#include "openssl/x509.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <dlfcn.h>

#include <XrdOuc/XrdOucString.hh>
#include <XrdSec/XrdSecEntity.hh>

#include "XrdVersion.hh"

XrdVERSIONINFO(XrdSecgsiAuthzFun,secgsiauthz);
XrdVERSIONINFO(XrdSecgsiAuthzKey,secgsiauthz);
XrdVERSIONINFO(XrdSecgsiAuthzInit,secgsiauthz);

extern "C"
{
#include "lcmaps_basic.h"

int XrdSecgsiAuthzInit(const char *cfg);
int XrdSecgsiAuthzFun(XrdSecEntity &entity);
}

#define policy_count 1
static const char policy_name [] = "xrootd_policy";

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
   std::lock_guard<std::mutex> guard(lcmaps_mutex);

   /* -1 is the mapcounter */
   // Need char, not const char.  Don't know if LCMAPS changes it.
   char  *pem_string_copy = strdup(entity.creds);
   char  *poolindex = NULL;
   uid_t  uid = -1;
   gid_t *pgid_list = NULL, *sgid_list = NULL;
   int    npgid = 0, nsgid = 0;

   // To manage const cast issues
   const char * policy_name_env = getenv("LCMAPS_POLICY_NAME");
   char * policy_name_copy = strdup(policy_name_env ? policy_name_env : policy_name);

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

   PRINT(inf_pfx << "Got uid " << uid);
   struct passwd * pw = getpwuid(uid);
   // If LCMAPS allows the mapping - but we're missing a username, we proceed.
   // The certificate was valid; we just treat this as an unmapped user in the
   // Xrootd framework.
   if (pw == NULL) {
      return 0;
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

   X509 *cert;
   STACK_OF(X509*) chain;
   if (!globus_get_cert_and_chain(entity.creds, entity.credslen, &cert, &chain)) {
      PRINT(err_pfx << "Failed to parse certificate chain.");
      return -1;
   }

   std::string skey = GetKey(cert, chain, entity);

   X509_free(cert);
   sk_X509_pop_free(chain, X509_free);

   if (skey.empty()) {
      PRINT(err_pfx << "Key verification failed.");
      return -1;
   }
   *key = new char[skey.length()+1];
   memcpy(*key, skey.c_str(), skey.length());
   (*key)[skey.length()] = '\0';
   PRINT(inf_pfx << "Returning '" << skey << "' of length " << skey.length() << " as key.");
   return skey.length() + 1;
}


//
// Init the relevant parameters from a dedicated config file
//
int XrdSecgsiAuthzInit(const char *cfg)
{
   int retval = XrdSecgsiAuthzConfig(cfg);
   if (retval) {return retval;}

   if (!globus_activate()) {return -1;}

   // Done
   // 1 means 'OK and I want the certificate in PEM base64 format'
   return g_certificate_format;
}
