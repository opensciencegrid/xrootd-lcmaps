
/**
 * This file contains various support functions for validating a credential
 * via the Globus libraries.
 */

#include "globus/globus_gsi_system_config.h"
#include "globus/globus_gsi_cert_utils.h"
#include "globus/globus_gsi_credential.h"
#include "globus/globus_module.h"

#include <iostream>
#include <mutex>

std::mutex initializer_mutex;
bool g_globus_initialized = false;

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
  g_globus_initialized = true;
  return true;
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


bool globus_deactivate() {
  std::lock_guard<std::mutex> guard(initializer_mutex);
  if (!g_globus_initialized) {return false;}

  globus_module_deactivate(GLOBUS_GSI_SYSCONFIG_MODULE);
  globus_module_deactivate(GLOBUS_GSI_CALLBACK_MODULE);
  globus_module_deactivate(GLOBUS_GSI_CREDENTIAL_MODULE);
  globus_module_deactivate(GLOBUS_GSI_CERT_UTILS_MODULE);

  g_globus_initialized = false;
  return true;
}


struct authz_state {

  globus_gsi_cred_handle_t m_cred = nullptr;
  globus_gsi_callback_data_t m_callback = nullptr;
  char *m_subject;

  ~authz_state() {
    if (m_cred) {globus_gsi_cred_handle_destroy(m_cred);}
    if (m_callback) {globus_gsi_callback_data_destroy(m_callback);}
    if (m_subject) {OPENSSL_free(m_subject);}
  }

};

bool globus_verify(X509* cert, STACK_OF(X509*) chain, char** dn) {
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

 
  // Setup Globus callback object; required boilerplait that appears to
  // be necessary for each invocation.
  result = globus_gsi_callback_data_init(&state.m_callback);
  if (GLOBUS_SUCCESS != result) {
    globus_print(result);
    return false;
  }
  char *cert_dir;
  result = globus_gsi_sysconfig_get_cert_dir_unix(&cert_dir);
  if (GLOBUS_SUCCESS != result) {
    std::cerr << "Failed to determine trusted certificates directory.\n";
    globus_print(result);
    return false;
  }
  result = globus_gsi_callback_set_cert_dir(state.m_callback, cert_dir);
  free(cert_dir);
  if (GLOBUS_SUCCESS != result) {
    globus_print(result);
    return false;
  }

  // Verify credential chain.
  result = globus_gsi_cred_verify_cert_chain(state.m_cred, state.m_callback);
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

