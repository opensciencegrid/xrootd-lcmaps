
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
 * Alternate version of globus_verify
 * - `creds`: PEM-formatted version of the credential chain.
 */
bool globus_verify(const char * creds, char **dn);

#endif  // __GLOBUS_SUPPORT_H_
