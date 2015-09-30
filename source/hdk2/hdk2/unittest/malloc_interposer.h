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

#ifndef __MALLOC_INTERPOSER__
#define __MALLOC_INTERPOSER__

#ifndef _MSC_VER
#  include <dlfcn.h>

#  ifdef __APPLE__
#    define LIB_EXT "dylib"
#  else
#    define LIB_EXT "so"
#  endif

/*
    Note: The clearstats() method is called from a dynamically loaded module to avoid any linking with the interposer library.
    Directly linking with the interposer will result in function interposition every time the binary is run.  In other words, a user cannot
    control the interposition via the LD_PRELOAD variable, which is undesirable.  This header is simply meant to be ease the use of the
    clearstats() API with as little change to the malloc_interposer library as possible.
*/

typedef void (*fnClearStats)(void);

#  define clear_interposer_stats() \
{ \
    void* pMallocInterposer = dlopen("malloc_interposer." LIB_EXT, RTLD_LAZY); \
    if (NULL != pMallocInterposer) \
    { \
        void* p = dlsym(pMallocInterposer, "clearstats"); \
        if (NULL != p) \
        { \
            fnClearStats clearstats = NULL; \
            memcpy(&clearstats, &p, sizeof(fnClearStats)); \
            clearstats(); \
        } \
        dlclose(pMallocInterposer); \
    } \
}
#else
#  define clear_interposer_stats() /* no-op */
#endif /* ndef _MSC_VER */

#endif /* ndef __MALLOC_INTERPOSER__ */
