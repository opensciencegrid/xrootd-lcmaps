
/**
 * This file contains various support functions for validating a credential
 * via the Globus libraries.
 */

#include "globus/globus_gsi_system_config.h"
#include "globus/globus_gsi_cert_utils.h"
#include "globus/globus_gsi_credential.h"
#include "globus/globus_gsi_callback_constants.h"
#include "globus/globus_module.h"

#include <atomic>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>

#include "GlobusError.hh"

std::mutex initializer_mutex;
bool g_globus_initialized = false;
char *g_cert_dir = nullptr;


inline uint64_t monotonic_time() {
  struct timespec tp;
#ifdef CLOCK_MONOTONIC_COARSE
  clock_gettime(CLOCK_MONOTONIC_COARSE, &tp);
#else
  clock_gettime(CLOCK_MONOTONIC, &tp);
#endif
  return tp.tv_sec + (tp.tv_nsec >= 500000000);
}


static void globus_print(globus_result_t result) {
  globus_object_t *error_obj = globus_error_get(result);
  if (error_obj == GLOBUS_ERROR_NO_INFO) {
    std::cerr << "Globus error occurred (no further information available)\n";
    return;
  }
  char *error_full = globus_error_print_chain(error_obj);
  if (!error_full) {
    std::cerr << "Globus error occurred (error unprintable)\n";
    return;
  }
  std::cerr << "Globus error: " << error_full << "\n";
  free(error_full);
}


bool globus_activate() {
  std::lock_guard<std::mutex> guard(initializer_mutex);

  if (GLOBUS_SUCCESS != globus_thread_set_model("pthread")) {
    std::cerr << "Failed to enable Globus thread model." << std::endl;
    return false;
  }
  if (GLOBUS_SUCCESS != globus_module_activate(GLOBUS_GSI_CERT_UTILS_MODULE)) {
    std::cerr << "Failed to activate Globus GSI cert utils module." << std::endl;
    return false;
  }
  if (GLOBUS_SUCCESS != globus_module_activate(GLOBUS_GSI_CREDENTIAL_MODULE)) {
    std::cerr << "Failed to activate Globus GSI credential module." << std::endl;
    globus_module_deactivate(GLOBUS_GSI_CERT_UTILS_MODULE);
    return false;
  }
  if (GLOBUS_SUCCESS != globus_module_activate(GLOBUS_GSI_CALLBACK_MODULE)) {
    std::cerr << "Failed to activate Globus GSI callback module." << std::endl;
    globus_module_deactivate(GLOBUS_GSI_CERT_UTILS_MODULE);
    globus_module_deactivate(GLOBUS_GSI_CREDENTIAL_MODULE);
    return false;
  }
  if (GLOBUS_SUCCESS != globus_module_activate(GLOBUS_GSI_SYSCONFIG_MODULE)) {
    std::cerr << "Failed to activate Globus GSI sysconfig module." << std::endl;
    globus_module_deactivate(GLOBUS_GSI_CERT_UTILS_MODULE);
    globus_module_deactivate(GLOBUS_GSI_CREDENTIAL_MODULE);
    globus_module_deactivate(GLOBUS_GSI_CALLBACK_MODULE);
    return false;
  }
  globus_result_t result = globus_gsi_sysconfig_get_cert_dir_unix(&g_cert_dir);
  if (GLOBUS_SUCCESS != result) {
    std::cerr << "Failed to determine trusted certificates directory.\n";
    globus_print(result);
    globus_module_deactivate(GLOBUS_GSI_SYSCONFIG_MODULE);
    globus_module_deactivate(GLOBUS_GSI_CERT_UTILS_MODULE);
    globus_module_deactivate(GLOBUS_GSI_CREDENTIAL_MODULE);
    globus_module_deactivate(GLOBUS_GSI_CALLBACK_MODULE);
    return false;
  }
  globus_module_deactivate(GLOBUS_GSI_SYSCONFIG_MODULE);

  g_globus_initialized = true;
  return true;
}


bool globus_deactivate() {
  std::lock_guard<std::mutex> guard(initializer_mutex);
  if (!g_globus_initialized) {return false;}

  globus_module_deactivate(GLOBUS_GSI_CALLBACK_MODULE);
  globus_module_deactivate(GLOBUS_GSI_CREDENTIAL_MODULE);
  globus_module_deactivate(GLOBUS_GSI_CERT_UTILS_MODULE);

  free(g_cert_dir);
  g_cert_dir = nullptr;

  g_globus_initialized = false;
  return true;
}


namespace {
struct GlobusCleanup {
  ~GlobusCleanup() {globus_deactivate();}
};
GlobusCleanup cleanup_helper;
}

namespace {

class Verify;
class CertStore;

class VerifyCtx {
  friend class Verify;
  friend class CertStore;

  VerifyCtx(const VerifyCtx&) = delete;

  VerifyCtx() {
    globus_result_t result = GLOBUS_SUCCESS;
    m_store_context = X509_STORE_CTX_new();
    if (!m_store_context) {
      result = GLOBUS_FAILURE;
      throw result;
    }

    globus_gsi_callback_get_X509_STORE_callback_data_index(&m_callback_data_index);
  }

  void acquire(X509_STORE * cert_store) {m_cert_store = cert_store;}

  void release() {m_cert_store = nullptr;}

  globus_result_t operator() (globus_gsi_cred_handle_t cred_handle)
  {
    static const char * _function_name_ = "VerifyCtx::operator()";

    globus_result_t result = GLOBUS_SUCCESS;

    X509 *cert = nullptr;
    if (GLOBUS_SUCCESS != (result = globus_gsi_cred_get_cert(cred_handle, &cert))) {
      return result;
    }

    STACK_OF(X509) *cert_chain = nullptr;
    if (GLOBUS_SUCCESS != (result = globus_gsi_cred_get_cert_chain(cred_handle, &cert_chain))) {
      return result;
    }

    // Initialize GSI callback data
    std::unique_ptr<globus_gsi_callback_data_t, DeleteGsiCallbackData> callback_data(new globus_gsi_callback_data_t);
    result = globus_gsi_callback_data_init(callback_data.get());
    if (GLOBUS_SUCCESS != result) {
      globus_print(result);
      return result;
    }
    result = globus_gsi_callback_set_cert_dir(*callback_data, g_cert_dir);
    if (GLOBUS_SUCCESS != result) {
      globus_print(result);
      return result;
    }

    X509_STORE_CTX_init(m_store_context, m_cert_store, cert, cert_chain);
    X509_STORE_CTX_set_depth(m_store_context, GLOBUS_GSI_CALLBACK_VERIFY_DEPTH);
    X509_STORE_CTX_set_ex_data(
            m_store_context,
            m_callback_data_index,
            (void *)(*callback_data));
    X509_STORE_CTX_set_flags(m_store_context, X509_V_FLAG_ALLOW_PROXY_CERTS);

    if (!X509_verify_cert(m_store_context))
    {
      globus_result_t callback_error;
      globus_result_t local_result;

      GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
        result,
        GLOBUS_GSI_CRED_ERROR_VERIFYING_CRED,
        (_GCRSL("Failed to verify credential")));

      local_result = globus_gsi_callback_get_error(*callback_data,
                                                   &callback_error);
      if (local_result != GLOBUS_SUCCESS)
      {
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
          local_result,
          GLOBUS_GSI_CRED_ERROR_VERIFYING_CRED);
      }
      else
      {
        local_result = callback_error;
      }

      result = globus_i_gsi_cred_error_join_chains_result(
                result,
                local_result);
    }

    // Remove the reference to the cert_chain so we can safely free it.
    X509_STORE_CTX_set_chain(m_store_context, nullptr);
    sk_X509_pop_free(cert_chain, X509_free);
    X509_STORE_CTX_set_cert(m_store_context, nullptr);
    X509_free(cert);

    // _cleanup resets the state of the context but doesn't free the
    // dynamically allocated structures.
    X509_STORE_CTX_cleanup(m_store_context);

    return result;
  }

public:
  /**
   * VerifyCtx must be public in order for std::unique_ptr to delete an instance.
   */
  ~VerifyCtx() {
    if (m_store_context)
    {
      X509_STORE_CTX_free(m_store_context);
    }
  }

private:
  int m_callback_data_index;
  X509_STORE_CTX             *m_store_context = nullptr;
  X509_STORE                 *m_cert_store = nullptr;

  // Deletion function for unique_ptr<globus_gsi_callback_data_t>
  struct DeleteGsiCallbackData {
    void operator()(globus_gsi_callback_data_t *p) {
      if (*p) {
        globus_gsi_callback_data_destroy(*p);
        *p = nullptr;
      }
      delete p;
    }
  };

};


class CertStore;

/**
 * A simple RAII-style class that holds the state and lock necessary to
 * for certificate chain verification.
 *
 * Meant to be constructed by a static CertStore
 */
class Verify
{
friend class CertStore;
public:
  ~Verify();
  globus_result_t operator() (globus_gsi_cred_handle_t cred_handle);
  Verify(Verify &&) = default;

private:
  Verify(VerifyCtx &ctx, CertStore &store);
  Verify(const Verify&) = delete;

  VerifyCtx &m_ctx;
  CertStore &m_store;
};

class CertStore {
  friend class VerifyCtx;
  friend class Verify;

  CertStore(const CertStore&) = delete;

  CertStore()
  {
    //std::cerr << "Caching trust roots into memory\n";
    reload();
  }

  /**
   * Reload the trust roots from disk.
   */
  void reload()
  {
    std::lock_guard<std::mutex> guard(m_mutex);

    static const char _function_name_ [] = "CertStore::reload()";

    if (m_cert_store)
    {
        X509_STORE_free(m_cert_store);
    }
    m_cert_store = X509_STORE_new();
    if (m_cert_store == NULL)
    {
        globus_result_t result = GLOBUS_FAILURE;
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
                GLOBUS_GSI_CRED_ERROR_WITH_CALLBACK_DATA);
        throw result;
    }
    X509_STORE_set_verify_cb_func(m_cert_store,
                                  globus_gsi_callback_create_proxy_callback);
    X509_STORE_set_depth(m_cert_store, GLOBUS_GSI_CALLBACK_VERIFY_DEPTH);
    X509_STORE_set_flags(m_cert_store, X509_V_FLAG_ALLOW_PROXY_CERTS);
    #ifdef _OPENSSL111
        X509_STORE_set_check_issued(m_cert_store, globus_gsi_callback_check_issued);
    #else
	m_cert_store->check_issued = globus_gsi_callback_check_issued;
    #endif

    m_expire_time = monotonic_time() + m_expiry_secs;

    if (!X509_STORE_load_locations(m_cert_store, NULL, g_cert_dir))
    {
      globus_result_t result = GLOBUS_FAILURE;
      GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
        result,
        GLOBUS_GSI_CRED_ERROR_WITH_CALLBACK_DATA,
        (_GCRSL("Failed to initialize X509 store locations.")));
      throw result;
    }
  }

public:
  ~CertStore() {
    if (m_cert_store)
    {
        X509_STORE_free(m_cert_store);
    }
  }

  /**
   * Return a rvalue-ref to a Verify object, which will perform credential
   * verification.
   *
   * A few implementation notes:
   * - Every 10 minutes, this will reload the trust roots and CRLs from disk.
   * - This will hold up to 63 copies of the trust roots; the different threads
   *   in the program will be hashed to use different copies of the trust
   *   roots.  This way, we balance coarse-grained locking over a global with
   *   the memory consumption due to the CAs.
   * - The VerifyCtx object itself is a thread-local.
   */
  static Verify
  GetVerify() {
    std::hash<std::thread::id> hasher;
    size_t slot = hasher(std::this_thread::get_id()) % m_store_size;
    std::unique_ptr<CertStore> &store = m_store[slot];
    if (!store) {
      store.reset(new CertStore());
    }
    if (!m_ctx) {
      m_ctx.reset(new VerifyCtx());
    }

   uint64_t now = monotonic_time();
   if (now > store->m_expire_time) {
     store->m_expire_time = now + m_expiry_secs;
     //std::cerr << "Memory cache of trust roots expired; reloading\n";
     store->reload();
     //std::cerr << "Reload complete.\n";
   }

    return Verify(*m_ctx, *store);
  }

private:
  std::atomic<uint64_t> m_expire_time;
  std::mutex m_mutex;
  X509_STORE *m_cert_store = nullptr;
  static const unsigned m_store_size = 63;
  static const unsigned m_expiry_secs = 600;
  static std::array<std::unique_ptr<CertStore>, m_store_size> m_store;
  static thread_local std::unique_ptr<VerifyCtx> m_ctx;
};

std::array<std::unique_ptr<CertStore>, CertStore::m_store_size> CertStore::m_store;
thread_local std::unique_ptr<VerifyCtx> CertStore::m_ctx;

/// Implementation of the Verify class.
Verify::Verify(VerifyCtx &ctx, CertStore &store) :
  m_ctx(ctx),
  m_store(store)
{
  m_store.m_mutex.lock();
  m_ctx.acquire(m_store.m_cert_store);
}


Verify::~Verify() {
  m_ctx.release();
  m_store.m_mutex.unlock();
}


globus_result_t
Verify::operator() (globus_gsi_cred_handle_t cred_handle)
{
  return m_ctx(cred_handle);
}


struct authz_state
{
  globus_gsi_cred_handle_t m_cred = nullptr;
  char *m_subject = nullptr;
  BIO *m_bio = nullptr;

  ~authz_state() {
    if (m_cred) {globus_gsi_cred_handle_destroy(m_cred);}
    if (m_subject) {OPENSSL_free(m_subject);}
    if (m_bio) {BIO_free(m_bio);}
  }

};

}  // anonymous namespace


bool globus_verify(X509* cert, STACK_OF(X509*) chain, char** dn)
{
  if (dn) {*dn = NULL;}

  authz_state state;

  // Start of Globus proxy parsing and verification...
  globus_result_t result = globus_gsi_cred_handle_init(&state.m_cred, NULL);
  if (GLOBUS_SUCCESS != result) {
    globus_print(result);
    return false;
  }

  // Load up the current certificate chain into the credential object.
  result = globus_gsi_cred_set_cert(state.m_cred, cert);
  if (GLOBUS_SUCCESS != result) {
    globus_print(result);
    return false;
  }
  result = globus_gsi_cred_set_cert_chain(state.m_cred, chain);
  if (GLOBUS_SUCCESS != result) {
    globus_print(result);
    return false;
  }

  try {
    Verify verify(CertStore::GetVerify());
    result = verify(state.m_cred);
  } catch (globus_result_t result) {
    std::cerr << "Failed to create verification context.\n";
    globus_print(result);
    return result;
  }
  if (GLOBUS_SUCCESS != result) {
    std::cerr << "Failed to validate credentials.\n";
    globus_print(result);
    return false;
  }

  // Look through certificates to find an EEC (which has the subject)
  globus_gsi_cert_utils_cert_type_t cert_type;
  X509 *eec_cert = cert;
  result = globus_gsi_cert_utils_get_cert_type(cert, &cert_type);
  if (GLOBUS_SUCCESS != result) {
    globus_print(result);
    return false;
  }
  if (!(cert_type & GLOBUS_GSI_CERT_UTILS_TYPE_EEC)) {
    result = globus_gsi_cert_utils_get_identity_cert(chain, &eec_cert);
    if (GLOBUS_SUCCESS != result) {
      globus_print(result);
      return false;
    }
  }

  // From the EEC, use OpenSSL to determine the subject
  state.m_subject = X509_NAME_oneline(X509_get_subject_name(eec_cert), NULL, 0);
  if (!dn) {
    std::cerr << "Unable to determine certificate DN.\n";
    return false;
  }
  if (dn) {*dn = strdup(state.m_subject);}

  return true;
}


bool globus_get_cert_and_chain(const char * creds, size_t credslen, X509 **cert, STACK_OF(X509) **chain)
{
  if (cert) {*cert = nullptr;}
  if (chain) {*chain = nullptr;}

  authz_state state;

  globus_result_t result = globus_gsi_cred_handle_init(&state.m_cred, NULL);
  if (GLOBUS_SUCCESS != result) {
    globus_print(result);
    return false;
  }

  // OpenSSL wiki states that BIO_new_mem_buf results in a read-only object,
  // meaning the const_cast ought to be safe.
  state.m_bio = BIO_new_mem_buf(const_cast<char *>(creds), credslen);
  if (!state.m_bio) {
    std::cerr << "Unable to allocate new BIO object" << std::endl;
    return false;
  }

  result = globus_gsi_cred_read_cert_bio(state.m_cred, state.m_bio);
  if (GLOBUS_SUCCESS != result) {
    globus_print(result);
    return false;
  }

  if (GLOBUS_SUCCESS != (result = globus_gsi_cred_get_cert(state.m_cred, cert))) {
    globus_print(result);
    return false;
  }

  if (GLOBUS_SUCCESS != (result = globus_gsi_cred_get_cert_chain(state.m_cred, chain))) {
    globus_print(result);
    return false;
  }

  return true;
}
