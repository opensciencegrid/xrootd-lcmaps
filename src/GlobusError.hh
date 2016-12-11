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

#ifndef __GLOBUS_ERROR_H_
#define __GLOBUS_ERROR_H_

#include "globus/globus_common.h"

globus_result_t
globus_i_gsi_cred_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc);


globus_result_t
globus_i_gsi_cred_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc);


globus_result_t
globus_i_gsi_cred_error_join_chains_result(
    globus_result_t                     outter_error,
    globus_result_t                     inner_error);


#define GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(_RESULT_, _ERRORTYPE_, _ERRSTR_) \
    { \
        char *                          _tmp_str_ = \
            globus_common_create_string _ERRSTR_; \
        _RESULT_ = globus_i_gsi_cred_openssl_error_result(_ERRORTYPE_, \
                                                          __FILE__, \
                                                          _function_name_, \
                                                          __LINE__, \
                                                          _tmp_str_, \
                                                          NULL); \
        globus_libc_free(_tmp_str_); \
    }

#define GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(_TOP_RESULT_, _ERRORTYPE_) \
    _TOP_RESULT_ = globus_i_gsi_cred_error_chain_result(_TOP_RESULT_, \
                                                        _ERRORTYPE_, \
                                                        __FILE__, \
                                                        _function_name_, \
                                                        __LINE__, \
                                                        NULL, \
                                                        NULL)

#endif  // __GLOBUS_ERROR_H_
