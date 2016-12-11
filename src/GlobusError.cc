/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * This module copies over a few error object creation / formatting helper
 * functions from the Globus Toolkit.
 *
 * Both Xrootd-Lcmaps and Globus are Apache licensed, meaning this is a
 * valid use case.
 */
#include "globus/globus_error_openssl.h"
#include "globus/globus_gsi_credential.h"

extern char *
globus_l_gsi_cred_error_strings[GLOBUS_GSI_CRED_ERROR_LAST];

globus_result_t
globus_i_gsi_cred_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    error_object =
        globus_error_wrap_openssl_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            error_type,
            filename,
            function_name,
            line_number,
            "%s%s%s",
            _GCRSL(globus_l_gsi_cred_error_strings[error_type]),
            short_desc ? ": " : "",
            short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    return result;
}


globus_result_t
globus_i_gsi_cred_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    error_object =
        globus_error_construct_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            globus_error_get(chain_result),
            error_type,
            filename,
            function_name,
            line_number,
            "%s%s%s",
            _GCRSL(globus_l_gsi_cred_error_strings[error_type]),
            short_desc ? ": " : "",
            short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    return result;
}


globus_result_t
globus_i_gsi_cred_error_join_chains_result(
    globus_result_t                     outter_error,
    globus_result_t                     inner_error)
{
    globus_result_t                     result;
    globus_object_t *                   result_error_obj = NULL;
    globus_object_t *                   outter_error_obj = NULL;
    globus_object_t *                   inner_error_obj = NULL;
    globus_object_t *                   temp_error_obj = NULL;
    static char                         _function_name_ []=
        "globus_i_gsi_cred_error_join_chains";

    outter_error_obj = globus_error_get(outter_error);
    inner_error_obj = globus_error_get(inner_error);
    if(outter_error_obj && inner_error_obj)
    {
        temp_error_obj = outter_error_obj;
        while(globus_error_get_cause(temp_error_obj))
        {
            temp_error_obj = globus_error_get_cause(temp_error_obj);
        }

        temp_error_obj = globus_error_initialize_base(temp_error_obj,
                                                      globus_error_get_source(temp_error_obj),
                                                      inner_error_obj);
        result_error_obj = outter_error_obj;
    }
    else if(inner_error_obj)
    {
        result_error_obj = inner_error_obj;
    }
    else
    {
        result_error_obj = 
            globus_error_construct_error(
                GLOBUS_GSI_CREDENTIAL_MODULE,
                NULL,
                GLOBUS_GSI_CRED_ERROR_CREATING_ERROR_OBJ,
                __FILE__,
                _function_name_,
                __LINE__,
                "Couldn't join inner and outer error chains");
    }

    result = globus_error_put(result_error_obj);

    return result;
}

