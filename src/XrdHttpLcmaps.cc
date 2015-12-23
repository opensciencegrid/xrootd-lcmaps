
#include <iostream>

#include <openssl/ssl.h>

#include <XrdHttp/XrdHttpSecXtractor.hh>
#include <XrdVersion.hh>
#include <XrdSys/XrdSysPthread.hh>
#include <XrdSec/XrdSecEntity.hh>

extern "C" {
#include "lcmaps.h"
}

#include "XrdLcmapsConfig.hh"

#define policy_count 1
static const char default_db  [] = "/etc/lcmaps.db";
static const char default_policy_name [] = "xrootd_policy";
static const char plugin_name [] = "XrdSecgsiAuthz";

// `proxy_app_verify_callback` comes from libvomsapi (but isn't found in the
// headers).  It extends OpenSSL's built-in certificate verify function with
// support for `old-style` proxies.
extern "C" {
  extern int proxy_app_verify_callback(X509_STORE_CTX *ctx, void *empty);
}

XrdVERSIONINFO(XrdHttpGetSecXtractor,"lcmaps");

// Someday we'll actually hook into the Xrootd logging system...
#define PRINT(y)    std::cerr << y << "\n";

class XrdHttpLcmaps : public XrdHttpSecXtractor
{
public:

    virtual int GetSecData(XrdLink *, XrdSecEntity &entity, SSL *ssl)
    {
        static const char err_pfx[] = "ERROR in AuthzFun: ";
        static const char inf_pfx[] = "INFO in AuthzFun: ";

        // Per OpenSSL docs, the ref count of peer_chain is not incremented.
        // Hence, we do not free this later.
        STACK_OF(X509) * peer_chain = SSL_get_peer_cert_chain(ssl);

        // The refcount here is incremented.
        X509 * peer_certificate = SSL_get_peer_certificate(ssl);

        // No remote client?  Add nothing to the entity, but do not
        // fail.
        if (!peer_certificate) {return 0;}
        if (!peer_chain)
        {
            X509_free(peer_certificate);
            return 0;
        }

        STACK_OF(X509) * full_stack = sk_X509_new_null();
        sk_X509_push(full_stack, peer_certificate);
        for (int idx = 0; idx < sk_X509_num(peer_chain); idx++) {
            sk_X509_push(full_stack, sk_X509_value(peer_chain, idx)); 
        }

        // Grab the global mutex - lcmaps is not thread-safe.
        // TODO(bbockelm): Cache lookups
        XrdSysMutexHelper lock(&m_mutex);

        char  *poolindex = NULL;
        uid_t  uid = -1;
        gid_t *pgid_list = NULL, *sgid_list = NULL;
        int    npgid = 0, nsgid = 0;
        lcmaps_request_t request = NULL; // Typically, the RSL

        // To manage const cast issues
        char * policy_name_copy = strdup(default_policy_name);

        int rc = lcmaps_run_with_stack_of_x509_and_return_account(
            full_stack,
            -1, // mapcounter
            request,
            policy_count,
            &policy_name_copy,
            &uid,
            &pgid_list,
            &npgid,
            &sgid_list,
            &nsgid,
            &poolindex);

        if (policy_name_copy) {
            free(policy_name_copy);
        }

        sk_X509_free(full_stack);
        X509_free(peer_certificate);

        if (pgid_list) {free(pgid_list);}
        if (sgid_list) {free(sgid_list);}
        if (poolindex) {free(poolindex);}

        // If there's a client cert but LCMAPS fails, we _do_ want to
        // fail the whole thing.
        if (rc) {
            PRINT(err_pfx << "LCMAPS failed or denied mapping");
            return -1;
        }

        PRINT(inf_pfx << "Got uid " << uid);
        struct passwd * pw = getpwuid(uid);
        if (pw == NULL) {
            return -1;
        }

        free(entity.moninfo);
        entity.moninfo = entity.name;
        entity.name = strdup(pw->pw_name);

        return 0;
    }

    virtual int Init(SSL_CTX *sslctx, int)
    {
        // TODO(bbockelm): OpenSSL docs note that peer_chain is not available
        // in reused sessions.  We should build a session cache, but we just
        // disable sessions for now.
        SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_OFF);

        // Utilize VOMS's peer certificate verification function (which
        // supports old-style proxies).
        SSL_CTX_set_cert_verify_callback(sslctx, proxy_app_verify_callback, 0);
        return 0;
    }

    XrdHttpLcmaps(XrdSysError *)
    {
    }

    int Config(const char *cfg)
    {
        return XrdSecgsiAuthzConfig(cfg);
    }

private:

    XrdSysError *eDest;
    static XrdSysMutex m_mutex;

};


XrdSysMutex XrdHttpLcmaps::m_mutex;


extern "C" XrdHttpSecXtractor *XrdHttpGetSecXtractor(XrdHttpSecXtractorArgs)
{
    XrdHttpLcmaps *extractor = new XrdHttpLcmaps(eDest);
    if (extractor->Config(parms)) {
        delete extractor;
        return NULL;
    }
    return extractor;
}

