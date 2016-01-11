
#include <string>
#include <sstream>

#include <voms/voms_apic.h>

#include <openssl/crypto.h>

/**
 * Build a hash key from the DN and VOMS info.
 */
std::string
GetKey(X509 *cert, STACK_OF(X509*) chain)
{
    std::stringstream key;
    // Start with the DN
    char *dn = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    key << dn << "::";
    free(dn);

    // Parse VOMS data and append that.
    struct vomsdata *voms_ptr = VOMS_Init(NULL, NULL);
    int errcode = 0;
    if (VOMS_Retrieve(cert, chain, RECURSE_CHAIN, voms_ptr, &errcode))
    {
        return key.str();
    }

    for (int idx = 0; voms_ptr->data[idx] != NULL; idx++)
    {
        struct voms *it = voms_ptr->data[idx];
        if (!it->voname) {continue;}
        key << it->voname << ":";
        for (int idx2 = 0; it->std[idx2] != NULL; idx2++)
        {
            struct data *it2 = it->std[idx2];
            if (!it2->group) {continue;}
            key << it2->group;
            if (it2->role) {key << "Role=" << it2->role;}
            key << ",";
        }
        key << "::";
    }
    return key.str();
}

