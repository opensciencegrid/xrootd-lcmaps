
#include <string>
#include <sstream>
#include <iostream>

#include <string.h>

#include <voms/voms_apic.h>

#include <openssl/crypto.h>

#include "XrdLcmapsKey.hh"

/**
 * Build a hash key from the DN and VOMS info.
 */
std::string
GetKey(X509 *cert, STACK_OF(X509*) chain, XrdSecEntity &ent)
{
    std::stringstream key;
    std::stringstream grps;
    bool found_grp = false;
    // Start with the DN
    char *dn = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    key << dn << "::";
    free(dn);

    // Parse VOMS data and append that.
    struct vomsdata *voms_ptr = VOMS_Init(NULL, NULL);
    int errcode = 0;
    if (!VOMS_Retrieve(cert, chain, RECURSE_CHAIN, voms_ptr, &errcode))
    {
        char *errmsg = VOMS_ErrorMessage(voms_ptr, errcode, NULL, 0);
        std::cerr << "VOMS failure (" << errcode << "): " << errmsg << std::endl;
        free(errmsg);
        return key.str();
    }

    for (int idx = 0; voms_ptr->data[idx] != NULL; idx++)
    {
        struct voms *it = voms_ptr->data[idx];
        if (!it->voname) {continue;}
        if (!ent.vorg) {ent.vorg = strdup(it->voname);}
        key << it->voname << ":";
        for (int idx2 = 0; it->std[idx2] != NULL; idx2++)
        {
            struct data *it2 = it->std[idx2];
            if (!it2->group) {continue;}
            if (found_grp) {grps << " ";}
            else {found_grp = true;}
            grps << it2->group;
            key << it2->group;
            if (it2->role)
            {
                key << "/Role=" << it2->role;
                ent.role = strdup(it2->role);
            }
            key << ",";
        }
        key << "::";
    }
    VOMS_Destroy(voms_ptr);
    ent.grps = strdup(grps.str().c_str());
    return key.str();
}

