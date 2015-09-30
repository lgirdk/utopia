/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/*
 * Copyright (c) 2008-2010 Cisco Systems, Inc. All rights reserved.
 *
 * Cisco Systems, Inc. retains all right, title and interest (including all
 * intellectual property rights) in and to this computer program, which is
 * protected by applicable intellectual property laws.  Unless you have obtained
 * a separate written license from Cisco Systems, Inc., you are not authorized
 * to utilize all or a part of this computer program for any purpose (including
 * reproduction, distribution, modification, and compilation into object code),
 * and you must immediately destroy or return to Cisco Systems, Inc. all copies
 * of this computer program.  If you are licensed by Cisco Systems, Inc., your
 * rights to utilize this computer program are limited by the terms of that
 * license.  To obtain a license, please contact Cisco Systems, Inc.
 *
 * This computer program contains trade secrets owned by Cisco Systems, Inc.
 * and, unless unauthorized by Cisco Systems, Inc. in writing, you agree to
 * maintain the confidentiality of this computer program and related information
 * and to not disclose this computer program and related information to any
 * other person or entity.
 *
 * THIS COMPUTER PROGRAM IS PROVIDED AS IS WITHOUT ANY WARRANTIES, AND CISCO
 * SYSTEMS, INC. EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED,
 * INCLUDING THE WARRANTIES OF MERCHANTIBILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, TITLE, AND NONINFRINGEMENT.
 */

// actual_client.cpp - [Generated by hdkcli_cpp]

// Local header.
#include "actual_client.h"

using namespace HDK;

Cisco_A::CiscoStructStruct::CiscoStructStruct() throw() :
    Struct(HDK_XML_BuiltinElement_Unknown)
{
}

Cisco_A::CiscoStructStruct::CiscoStructStruct(HDK_XML_Struct* phdkstruct) throw() :
    Struct(phdkstruct)
{
}

HDK_XML_Int Cisco_A::CiscoStructStruct::get_a() const throw()
{
    return HDK_XML_GetEx_Int(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_a, 0);
}

void Cisco_A::CiscoStructStruct::set_a(HDK_XML_Int value) throw()
{
    (void)HDK_XML_Set_Int(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_a, value);
}

Cisco_A::IntArray Cisco_A::CiscoStructStruct::get_as() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_as);
}

void Cisco_A::CiscoStructStruct::set_as(const Cisco_A::IntArray& value) throw()
{
    (void)HDK_XML_SetEx_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_as, value);
}

const char* Cisco_A::CiscoStructStruct::get_b() const throw()
{
    return HDK_XML_GetEx_String(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_b, 0);
}

void Cisco_A::CiscoStructStruct::set_b(const char* value) throw()
{
    (void)HDK_XML_Set_String(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_b, value);
}

Cisco_A::StringArray Cisco_A::CiscoStructStruct::get_bs() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_bs);
}

void Cisco_A::CiscoStructStruct::set_bs(const Cisco_A::StringArray& value) throw()
{
    (void)HDK_XML_SetEx_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_bs, value);
}

enum Cisco_A::CiscoEnum Cisco_A::CiscoStructStruct::get_c() const throw()
{
    return (enum Cisco_A::CiscoEnum)ACTUAL_CLIENT_MOD_GetEx_Cisco_A_CiscoEnum(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_c, ACTUAL_CLIENT_MOD_Enum_Cisco_A_CiscoEnum__UNKNOWN__);
}

void Cisco_A::CiscoStructStruct::set_c(enum Cisco_A::CiscoEnum value) throw()
{
    (void)ACTUAL_CLIENT_MOD_Set_Cisco_A_CiscoEnum(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_c, (ACTUAL_CLIENT_MOD_Enum_Cisco_A_CiscoEnum)value);
}

Cisco_A::CiscoEnumArray Cisco_A::CiscoStructStruct::get_cs() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_cs);
}

void Cisco_A::CiscoStructStruct::set_cs(const Cisco_A::CiscoEnumArray& value) throw()
{
    (void)HDK_XML_SetEx_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_cs, value);
}

Cisco::CiscoStructStruct::CiscoStructStruct() throw() :
    Struct(HDK_XML_BuiltinElement_Unknown)
{
}

Cisco::CiscoStructStruct::CiscoStructStruct(HDK_XML_Struct* phdkstruct) throw() :
    Struct(phdkstruct)
{
}

HDK_XML_Int Cisco::CiscoStructStruct::get_a() const throw()
{
    return HDK_XML_GetEx_Int(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_a, 0);
}

void Cisco::CiscoStructStruct::set_a(HDK_XML_Int value) throw()
{
    (void)HDK_XML_Set_Int(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_a, value);
}

Cisco::IntArray Cisco::CiscoStructStruct::get_as() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_as);
}

void Cisco::CiscoStructStruct::set_as(const Cisco::IntArray& value) throw()
{
    (void)HDK_XML_SetEx_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_as, value);
}

const char* Cisco::CiscoStructStruct::get_b() const throw()
{
    return HDK_XML_GetEx_String(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_b, 0);
}

void Cisco::CiscoStructStruct::set_b(const char* value) throw()
{
    (void)HDK_XML_Set_String(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_b, value);
}

Cisco::StringArray Cisco::CiscoStructStruct::get_bs() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_bs);
}

void Cisco::CiscoStructStruct::set_bs(const Cisco::StringArray& value) throw()
{
    (void)HDK_XML_SetEx_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_bs, value);
}

enum Cisco::CiscoEnum Cisco::CiscoStructStruct::get_c() const throw()
{
    return (enum Cisco::CiscoEnum)ACTUAL_CLIENT_MOD_GetEx_Cisco_CiscoEnum(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_c, ACTUAL_CLIENT_MOD_Enum_Cisco_CiscoEnum__UNKNOWN__);
}

void Cisco::CiscoStructStruct::set_c(enum Cisco::CiscoEnum value) throw()
{
    (void)ACTUAL_CLIENT_MOD_Set_Cisco_CiscoEnum(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_c, (ACTUAL_CLIENT_MOD_Enum_Cisco_CiscoEnum)value);
}

Cisco::CiscoEnumArray Cisco::CiscoStructStruct::get_cs() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_cs);
}

void Cisco::CiscoStructStruct::set_cs(const Cisco::CiscoEnumArray& value) throw()
{
    (void)HDK_XML_SetEx_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_cs, value);
}

Cisco::CiscoActionStruct::CiscoActionStruct() throw() :
    Struct(ACTUAL_CLIENT_MOD_Element_Cisco_CiscoAction)
{
}

Cisco::CiscoStructStruct Cisco::CiscoActionStruct::get_a() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_a);
}

void Cisco::CiscoActionStruct::set_a(const Cisco::CiscoStructStruct& value) throw()
{
    (void)HDK_XML_SetEx_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_a, value);
}

Cisco::CiscoActionResponseStruct::CiscoActionResponseStruct() throw() :
    Struct(ACTUAL_CLIENT_MOD_Element_Cisco_CiscoAction)
{
}

enum Cisco::CiscoActionResult Cisco::CiscoActionResponseStruct::get_CiscoActionResult() const throw()
{
    return (enum Cisco::CiscoActionResult)ACTUAL_CLIENT_MOD_GetEx_Cisco_CiscoActionResult(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_CiscoActionResult, ACTUAL_CLIENT_MOD_Enum_Cisco_CiscoActionResult__UNKNOWN__);
}

Cisco::CiscoStructArray Cisco::CiscoActionResponseStruct::get_b() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_b);
}

Cisco::CiscoAction2Struct::CiscoAction2Struct() throw() :
    Struct(ACTUAL_CLIENT_MOD_Element_Cisco_CiscoAction2)
{
}

Cisco::CiscoStructArray Cisco::CiscoAction2Struct::get_in() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_in);
}

void Cisco::CiscoAction2Struct::set_in(const Cisco::CiscoStructArray& value) throw()
{
    (void)HDK_XML_SetEx_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_in, value);
}

HDK_XML_Int Cisco::CiscoAction2Struct::get_x() const throw()
{
    return HDK_XML_GetEx_Int(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_x, 0);
}

void Cisco::CiscoAction2Struct::set_x(HDK_XML_Int value) throw()
{
    (void)HDK_XML_Set_Int(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_x, value);
}

Cisco::CiscoAction2ResponseStruct::CiscoAction2ResponseStruct() throw() :
    Struct(ACTUAL_CLIENT_MOD_Element_Cisco_CiscoAction2)
{
}

enum Cisco::CiscoAction2Result Cisco::CiscoAction2ResponseStruct::get_CiscoAction2Result() const throw()
{
    return (enum Cisco::CiscoAction2Result)ACTUAL_CLIENT_MOD_GetEx_Cisco_CiscoAction2Result(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_CiscoAction2Result, ACTUAL_CLIENT_MOD_Enum_Cisco_CiscoAction2Result__UNKNOWN__);
}

Cisco::CiscoStructStruct Cisco::CiscoAction2ResponseStruct::get_out() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_out);
}

Cisco::BooleanArray Cisco::CiscoAction2ResponseStruct::get_extra() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_extra);
}

Cisco_A::CiscoActionStruct::CiscoActionStruct() throw() :
    Struct(ACTUAL_CLIENT_MOD_Element_Cisco_A_CiscoAction)
{
}

Cisco_A::CiscoStructStruct Cisco_A::CiscoActionStruct::get_a() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_a);
}

void Cisco_A::CiscoActionStruct::set_a(const Cisco_A::CiscoStructStruct& value) throw()
{
    (void)HDK_XML_SetEx_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_a, value);
}

Cisco_A::CiscoActionResponseStruct::CiscoActionResponseStruct() throw() :
    Struct(ACTUAL_CLIENT_MOD_Element_Cisco_A_CiscoAction)
{
}

enum Cisco_A::CiscoActionResult Cisco_A::CiscoActionResponseStruct::get_CiscoActionResult() const throw()
{
    return (enum Cisco_A::CiscoActionResult)ACTUAL_CLIENT_MOD_GetEx_Cisco_A_CiscoActionResult(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_CiscoActionResult, ACTUAL_CLIENT_MOD_Enum_Cisco_A_CiscoActionResult__UNKNOWN__);
}

Cisco_A::CiscoStructArray Cisco_A::CiscoActionResponseStruct::get_b() const throw()
{
    return HDK_XML_Get_Struct(GetStruct(), ACTUAL_CLIENT_MOD_Element_Cisco_A_b);
}

bool HDK::InitializeClient() throw()
{
    return !!HDK_CLI_Init();
}

void HDK::UninitializeClient() throw()
{
    HDK_CLI_Cleanup();
}

HDK::ClientError Cisco::CiscoAction
(
    HDK::ITarget* pTarget,
    const Cisco::CiscoActionStruct & input,
    Cisco::CiscoActionResponseStruct & output,
    enum Cisco::CiscoActionResult* presult /* = NULL */,
    unsigned int timeoutSecs /* = 0 */
) throw()
{
    if (!pTarget)
    {
        return ClientError_InvalidArg;
    }

    ClientError error = pTarget->Request(timeoutSecs,
                                         ACTUAL_CLIENT_MOD_Module(),
                                         ACTUAL_CLIENT_MOD_MethodEnum_Cisco_CiscoAction,
                                         input,
                                         &output);

    const HDK_MOD_Method* pMethod = HDK_MOD_GetMethod(ACTUAL_CLIENT_MOD_Module(), ACTUAL_CLIENT_MOD_MethodEnum_Cisco_CiscoAction);

    // Get the result value.
    enum Cisco::CiscoActionResult result = output.get_CiscoActionResult();
    if (NULL != presult)
    {
        *presult = result;
    }

    // Determine if there was an HNAP-result, and whether it was an error or not.
    if ((ClientError_OK == error) && (HDK_XML_BuiltinElement_Unknown != pMethod->hnapResultElement))
    {
        if ((pMethod->hnapResultOK != (int)result) && (pMethod->hnapResultREBOOT != (int)result))
        {
            // An HNAP error response.
            error = HDK::ClientError_HnapMethod;
        }
    }

    return error;
}

HDK::ClientError Cisco::CiscoAction2
(
    HDK::ITarget* pTarget,
    const Cisco::CiscoAction2Struct & input,
    Cisco::CiscoAction2ResponseStruct & output,
    enum Cisco::CiscoAction2Result* presult /* = NULL */,
    unsigned int timeoutSecs /* = 0 */
) throw()
{
    if (!pTarget)
    {
        return ClientError_InvalidArg;
    }

    ClientError error = pTarget->Request(timeoutSecs,
                                         ACTUAL_CLIENT_MOD_Module(),
                                         ACTUAL_CLIENT_MOD_MethodEnum_Cisco_CiscoAction2,
                                         input,
                                         &output);

    const HDK_MOD_Method* pMethod = HDK_MOD_GetMethod(ACTUAL_CLIENT_MOD_Module(), ACTUAL_CLIENT_MOD_MethodEnum_Cisco_CiscoAction2);

    // Get the result value.
    enum Cisco::CiscoAction2Result result = output.get_CiscoAction2Result();
    if (NULL != presult)
    {
        *presult = result;
    }

    // Determine if there was an HNAP-result, and whether it was an error or not.
    if ((ClientError_OK == error) && (HDK_XML_BuiltinElement_Unknown != pMethod->hnapResultElement))
    {
        if ((pMethod->hnapResultOK != (int)result) && (pMethod->hnapResultREBOOT != (int)result))
        {
            // An HNAP error response.
            error = HDK::ClientError_HnapMethod;
        }
    }

    return error;
}

HDK::ClientError Cisco_A::CiscoAction
(
    HDK::ITarget* pTarget,
    const Cisco_A::CiscoActionStruct & input,
    Cisco_A::CiscoActionResponseStruct & output,
    enum Cisco_A::CiscoActionResult* presult /* = NULL */,
    unsigned int timeoutSecs /* = 0 */
) throw()
{
    if (!pTarget)
    {
        return ClientError_InvalidArg;
    }

    ClientError error = pTarget->Request(timeoutSecs,
                                         ACTUAL_CLIENT_MOD_Module(),
                                         ACTUAL_CLIENT_MOD_MethodEnum_Cisco_A_CiscoAction,
                                         input,
                                         &output);

    const HDK_MOD_Method* pMethod = HDK_MOD_GetMethod(ACTUAL_CLIENT_MOD_Module(), ACTUAL_CLIENT_MOD_MethodEnum_Cisco_A_CiscoAction);

    // Get the result value.
    enum Cisco_A::CiscoActionResult result = output.get_CiscoActionResult();
    if (NULL != presult)
    {
        *presult = result;
    }

    // Determine if there was an HNAP-result, and whether it was an error or not.
    if ((ClientError_OK == error) && (HDK_XML_BuiltinElement_Unknown != pMethod->hnapResultElement))
    {
        if ((pMethod->hnapResultOK != (int)result) && (pMethod->hnapResultREBOOT != (int)result))
        {
            // An HNAP error response.
            error = HDK::ClientError_HnapMethod;
        }
    }

    return error;
}
