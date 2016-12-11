#ifndef __XRD_LCMAPS_KEY_HH_
#define __XRD_LCMAPS_KEY_HH_

#include <string>

#include <openssl/crypto.h>

#include <XrdSec/XrdSecEntity.hh>

extern "C" {
int XrdSecgsiAuthzKey(XrdSecEntity &entity, char **key);
}

std::string GetKey(X509 *cert, STACK_OF(X509) *chain, XrdSecEntity &entity);

#endif
