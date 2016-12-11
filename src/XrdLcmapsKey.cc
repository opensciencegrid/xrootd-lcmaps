
#include <string>
#include <sstream>
#include <iostream>

#include <string.h>

#include <voms/voms_apic.h>

#include <openssl/crypto.h>

#include "GlobusSupport.hh"
#include "XrdLcmapsKey.hh"

/**
 * Build a hash key from the DN and VOMS info.
 */
std::string
GetKey(X509 *cert, STACK_OF(X509) *chain, XrdSecEntity &ent)
{
    std::stringstream key;
    std::stringstream grps;
    bool found_grp = false;

    // This plugin overrides any prior group information.
    free(ent.vorg); ent.vorg = nullptr;
    free(ent.role); ent.role = nullptr;
    free(ent.grps); ent.grps = nullptr;
    free(ent.endorsements); ent.endorsements = nullptr;

    // Start with the DN
    char *dn = nullptr;
    if (!globus_verify(cert, chain, &dn)) {
        std::cerr << "Globus chain verification failure.\n";
        return "";
    }

    // Set the monitoring information to be equal to the DN.
    free(ent.moninfo); ent.moninfo = strdup(dn);

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
        VOMS_Destroy(voms_ptr);
        return key.str();
    }

    bool found_fqan = false;
    std::stringstream endorsements;
    for (int idx = 0; voms_ptr->data[idx] != nullptr; idx++)
    {
        struct voms *it = voms_ptr->data[idx];
        if (!it->voname) {continue;}
        if (!ent.vorg) {ent.vorg = strdup(it->voname);}
        key << it->voname << ":";
        for (int idx2 = 0; it->std[idx2] != nullptr; idx2++)
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
        for (int idx2 = 0; it->fqan[idx2] != nullptr; idx2++)
        {
            if (found_fqan) {endorsements << ",";}
            else {found_fqan = true;}
            endorsements << it->fqan[idx2];
        }

        key << "::";
    }

    VOMS_Destroy(voms_ptr);
    if (found_grp)
    {
        ent.grps = strdup(grps.str().c_str());
    }
    if (found_fqan)
    {
        ent.endorsements = strdup(endorsements.str().c_str());
    }
    return key.str();
}

