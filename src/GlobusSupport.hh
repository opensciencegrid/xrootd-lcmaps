
#ifndef __GLOBUS_SUPPORT_H_
#define __GLOBUS_SUPPORT_H_

/**
 * Activate the globus modules.  Returns true on success and false otherwise.
 */
bool globus_activate();

/**
 * Deactivate the globus modules.  Returns true on success and false otherwise.
 */
bool globus_deactivate();

/**Validate a x509 chain using the globus libraries.
 * - `cert` is the client certificate used to authenticate the
 *   TLS connection.
 * - `chain` is the remainder of the chain.
 * - `dn` is the output variable; it is the traditional Globus representation
 *   of the DN.  Only filled in if globus_verify returns true.
 * - Returns true on success and false otherwise.
 */
bool globus_verify(X509* cert, STACK_OF(X509*) chain, char **dn);

/**
 * Uses Globus to create a cert and chain from a PEM-formatted string in memory.
 * - `creds`: PEM-formatted version of the credential chain.
 * - `cert`: Output variable; last certificate in creds.  Must be freed with
 *    X509_free.
 * - `chain`: Output variable; last N-1 certificates in creds.  Must be freed
 *    with sk_X509_free.
 *
 * Returns false on failure.
 */
bool globus_get_cert_and_chain(const char * creds, size_t credslen, X509 **cert, STACK_OF(X509) **chain);

#endif  // __GLOBUS_SUPPORT_H_
