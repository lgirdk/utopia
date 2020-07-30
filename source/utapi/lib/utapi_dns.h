/**********************************************************************
 * Copyright 2018-2019 ARRIS Enterprises, LLC.
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
 *********************************************************************/
#ifndef _UTAPI_DNS_H_
#define _UTAPI_DNS_H_

#include "utapi.h"

typedef struct dns_server
{
    unsigned long ins_num;
    char alias[256];
    boolean_t enable;
    char ip_address[64];
    char interface[64];
    char type[64];
} dns_server_t, relay_forward_t;

int Utopia_GetNumberOfDnsServers(UtopiaContext *ctx);
int Utopia_GetDnsServerByIndex(UtopiaContext *ctx, unsigned long ulIndex, dns_server_t *dns);
int Utopia_SetDnsServerByIndex(UtopiaContext *ctx, unsigned long ulIndex, const dns_server_t *dns);
int Utopia_GetDnsServerInsNumByIndex(UtopiaContext *ctx, unsigned long uIndex, int *ins);
int Utopia_GetDnsServerIndexByInsNum(UtopiaContext *ctx, int ins, unsigned long *uIndex);
int Utopia_AddDnsServer(UtopiaContext *ctx, const dns_server_t *dns);
int Utopia_RemoveDnsServer(UtopiaContext *ctx, unsigned long ins);

int Utopia_GetNumberOfDnsForwards(UtopiaContext *ctx);
int Utopia_GetDnsForwardByIndex(UtopiaContext *ctx, unsigned long ulIndex, relay_forward_t *forward);
int Utopia_SetDnsForwardByIndex(UtopiaContext *ctx, unsigned long ulIndex, const relay_forward_t *forward);
int Utopia_GetDnsForwardInsNumByIndex(UtopiaContext *ctx, unsigned long uIndex, int *ins);
int Utopia_GetDnsForwardIndexByInsNum(UtopiaContext *ctx, int ins, unsigned long *uIndex);
int Utopia_AddDnsForward(UtopiaContext *ctx, const relay_forward_t *forward);
int Utopia_RemoveDnsForward(UtopiaContext *ctx, unsigned long ins);
int Utopia_GetDnsRelayEnabled(UtopiaContext *ctx, boolean_t *enabled);
int Utopia_SetDnsRelayEnabled(UtopiaContext *ctx, boolean_t enabled);
#endif
