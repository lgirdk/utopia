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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utctx/utctx.h>
#include <utctx/utctx_api.h>
#include "utapi.h"
#include "utapi_util.h"
#include "utapi_wlan.h"
#include "DM_TR181.h"
#include "utapi_dns.h"

static int g_Dns_ServerCount = 0;
int Utopia_GetNumberOfDnsServers(UtopiaContext *ctx)
{
    if(g_Dns_ServerCount == 0)
    {
        Utopia_GetInt(ctx, UtopiaValue_Dns_StaticServerCount, &g_Dns_ServerCount);
    }
    return g_Dns_ServerCount;
}

int Utopia_GetDnsServerByIndex(UtopiaContext *ctx, unsigned long ulIndex, dns_server_t *dns)
{
    int ins_num = 0;
    int index = ulIndex + 1;

    if ((index > g_Dns_ServerCount) || (index < 1))
    {
        return -1;
    }

    Utopia_GetIndexedInt(ctx, UtopiaValue_Dns_StaticServer_InsNum, index, &ins_num);
    dns->ins_num = ins_num;
    Utopia_GetIndexed(ctx, UtopiaValue_Dns_StaticServer_Alias, index, dns->alias, sizeof(dns->alias));
    Utopia_GetIndexedBool(ctx, UtopiaValue_Dns_StaticServer_Enable, index, &dns->enable);
    Utopia_GetIndexed(ctx, UtopiaValue_Dns_StaticServer_IPAddress, index, dns->ip_address, sizeof(dns->ip_address));
    Utopia_GetIndexed(ctx, UtopiaValue_Dns_StaticServer_Interface, index, dns->interface, sizeof(dns->interface));
    Utopia_GetIndexed(ctx, UtopiaValue_Dns_StaticServer_Type, index, dns->type, sizeof(dns->type));

    return 0;
}

int Utopia_SetDnsServerByIndex(UtopiaContext *ctx, unsigned long ulIndex, const dns_server_t *dns)
{
    int index = ulIndex + 1;

    if ((index > g_Dns_ServerCount) || (index < 1))
    {
        return -1;
    }

    snprintf(s_tokenbuf, sizeof(s_tokenbuf), "dns_%d", index);
    Utopia_SetIndexed(ctx, UtopiaValue_Dns_StaticServer, index, s_tokenbuf);

    Utopia_SetIndexedInt(ctx, UtopiaValue_Dns_StaticServer_InsNum, index, dns->ins_num);
    Utopia_SetIndexed(ctx, UtopiaValue_Dns_StaticServer_Alias, index, (char*)dns->alias);
    Utopia_SetIndexedBool(ctx, UtopiaValue_Dns_StaticServer_Enable, index, dns->enable);
    Utopia_SetIndexed(ctx, UtopiaValue_Dns_StaticServer_IPAddress, index, (char*)dns->ip_address);
    Utopia_SetIndexed(ctx, UtopiaValue_Dns_StaticServer_Interface, index, (char*)dns->interface);
    Utopia_SetIndexed(ctx, UtopiaValue_Dns_StaticServer_Type, index, (char*)dns->type);

    return 0;
}

int Utopia_GetDnsServerInsNumByIndex(UtopiaContext *ctx, unsigned long ulIndex, int *ins)
{
    return Utopia_GetIndexedInt(ctx, UtopiaValue_Dns_StaticServer_InsNum, ulIndex + 1, ins);
}

int Utopia_GetDnsServerIndexByInsNum(UtopiaContext *ctx, int ins, unsigned long *ulIndex)
{
    int i = 0;
    int ins_num = 0;

    for (; i < g_Dns_ServerCount; i++)
    {
        Utopia_GetDnsServerInsNumByIndex(ctx, i, &ins_num);
        if (ins_num == ins) {
            *ulIndex = i;
            return 0;
        }
    }

    return -1;
}

int Utopia_AddDnsServer(UtopiaContext *ctx, const dns_server_t *dns)
{
    int count = Utopia_GetNumberOfDnsServers(ctx);
    Utopia_SetInt(ctx, UtopiaValue_Dns_StaticServerCount, ++g_Dns_ServerCount);
    Utopia_SetDnsServerByIndex(ctx, count, dns);

    return 0;
}

int Utopia_RemoveDnsServer(UtopiaContext *ctx, unsigned long ins)
{
    int count = 0;
    int index = 0;

    count = Utopia_GetNumberOfDnsServers(ctx);
    for (; index < count; index++)
    {
        int ins_num = 0;
        Utopia_GetDnsServerInsNumByIndex(ctx, index, &ins_num);
        if (ins_num == (int)ins)
        {
            break;
        }
    }

    if (index >= count)
    {
        return -1;
    }

    if (index < count - 1)
    {
        for (; index < count - 1; index++)
        {
            dns_server_t dns = {};
            Utopia_GetDnsServerByIndex(ctx, index + 1, &dns);
            Utopia_SetDnsServerByIndex(ctx, index, &dns);
        }
    }

    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_StaticServer_InsNum, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_StaticServer_Alias, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_StaticServer_Enable, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_StaticServer_IPAddress, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_StaticServer_Interface, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_StaticServer_Type, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_StaticServer, count);

    g_Dns_ServerCount--;
    Utopia_SetInt(ctx, UtopiaValue_Dns_StaticServerCount, g_Dns_ServerCount);

    return 0;
}
/* LGI ADD END */

int Utopia_Get_DeviceDnsRelayForwarding(UtopiaContext *pCtx, int index, void *str_handle)
{
    int iVal = -1;
    char tokenBuf[64] = {'\0'};
    char tokenVal[64] = {'\0'};
    if(!str_handle){
	sprintf(ulog_msg, "%s: Invalid Input Parameter", __FUNCTION__);
	ulog_error(ULOG_CONFIG, UL_UTAPI, ulog_msg);
        return ERR_INVALID_ARGS;
    }
    Obj_Device_DNS_Relay *deviceDnsRelay = (Obj_Device_DNS_Relay*)str_handle;

    sprintf(tokenBuf, "tr_dns_relay_forwarding_enable_%d", index);
    tokenBuf[strlen(tokenBuf)] = '\0';
    Utopia_RawGet(pCtx, NULL, tokenBuf, tokenVal, sizeof(tokenVal));
    deviceDnsRelay->Enable = (!strncasecmp(tokenVal, "false", 5))? FALSE : TRUE ;  
    sprintf(ulog_msg, "%s: Get Enable key & val = %s, %u", __FUNCTION__, tokenBuf, deviceDnsRelay->Enable);
    ulog_error(ULOG_CONFIG, UL_UTAPI, ulog_msg);
    
    memset(tokenBuf, 0, sizeof(tokenBuf));
    memset(tokenVal, 0, sizeof(tokenVal));
    sprintf(tokenBuf, "tr_dns_relay_forwarding_server_%d", index);
    tokenBuf[strlen(tokenBuf)] = '\0';
    Utopia_RawGet(pCtx, NULL, tokenBuf, tokenVal, sizeof(tokenVal));
    deviceDnsRelay->DNSServer.Value = inet_addr(tokenVal);
    
    memset(tokenBuf, 0, sizeof(tokenBuf));
    memset(tokenVal, 0, sizeof(tokenVal));
    sprintf(tokenBuf, "tr_dns_relay_forwarding_interface_%d", index);
    tokenBuf[strlen(tokenBuf)] = '\0';
    Utopia_RawGet(pCtx, NULL, tokenBuf, tokenVal, sizeof(tokenVal));
    tokenVal[strlen(tokenVal)] = '\0';
    strcpy(deviceDnsRelay->Interface, tokenVal);

    return UT_SUCCESS;
}

int Utopia_Set_DeviceDnsRelayForwarding(UtopiaContext *pCtx, int index, void *str_handle)
{
    int iVal = -1;
    char tokenBuf[64] = {'\0'};
    char tokenVal[64] = {'\0'};
    char cmd[128] = {'\0'};
    if (!pCtx || !str_handle) {
	sprintf(ulog_msg, "%s: Invalid Input Parameter", __FUNCTION__);
	ulog_error(ULOG_CONFIG, UL_UTAPI, ulog_msg);
        return ERR_INVALID_ARGS;
    }
    Obj_Device_DNS_Relay *deviceDnsRelay = (Obj_Device_DNS_Relay*)str_handle;

    sprintf(tokenBuf, "tr_dns_relay_forwarding_enable_%d", index);
    tokenBuf[strlen(tokenBuf)] = '\0';
    sprintf(ulog_msg, "%s: Set Enable key & val = %s, %u", __FUNCTION__, tokenBuf, deviceDnsRelay->Enable);
    ulog_error(ULOG_CONFIG, UL_UTAPI, ulog_msg);
    if(deviceDnsRelay->Enable == FALSE){
        sprintf(ulog_msg, "%s: Enable is FALSE \n", __FUNCTION__, tokenBuf);
	ulog_error(ULOG_CONFIG, UL_UTAPI, ulog_msg);
        Utopia_RawSet(pCtx, NULL, tokenBuf, "false");
    }else{
        sprintf(ulog_msg, "%s: Enable is TRUE \n", __FUNCTION__, tokenBuf);
	ulog_error(ULOG_CONFIG, UL_UTAPI, ulog_msg);
        Utopia_RawSet(pCtx, NULL, tokenBuf, "true");
    }
    memset(tokenBuf, 0, sizeof(tokenBuf));
    memset(tokenVal, 0, sizeof(tokenVal));
    sprintf(tokenBuf, "tr_dns_relay_forwarding_server_%d", index);
    tokenBuf[strlen(tokenBuf)] = '\0';
    sprintf(tokenVal, "%d.%d.%d.%d", 
                      (deviceDnsRelay->DNSServer.Value) & 0xFF,
                      (deviceDnsRelay->DNSServer.Value >> 8)  & 0xFF,
                      (deviceDnsRelay->DNSServer.Value >> 16) & 0xFF,
                      (deviceDnsRelay->DNSServer.Value >> 24) & 0xFF );
    tokenVal[strlen(tokenVal)] = '\0';
    Utopia_RawSet(pCtx, NULL, tokenBuf, tokenVal);

    memset(tokenBuf, 0, sizeof(tokenBuf));
    memset(tokenVal, 0, sizeof(tokenVal));
    sprintf(tokenBuf, "tr_dns_relay_forwarding_interface_%d", index);
    tokenBuf[strlen(tokenBuf)] = '\0';
    strncpy(tokenVal, deviceDnsRelay->Interface, strlen(deviceDnsRelay->Interface));
    tokenVal[strlen(deviceDnsRelay->Interface)] = '\0';
    Utopia_RawSet(pCtx, NULL, tokenBuf, tokenVal);
    
    return UT_SUCCESS;
}
static int g_Dns_ForwardCount = 0;

int Utopia_GetNumberOfDnsForwards(UtopiaContext *ctx)
{
    if(g_Dns_ForwardCount == 0)
    {
        Utopia_GetInt(ctx, UtopiaValue_Dns_ForwardCount, &g_Dns_ForwardCount);
    }
    return g_Dns_ForwardCount;
}

int Utopia_GetDnsForwardByIndex(UtopiaContext *ctx, unsigned long ulIndex, relay_forward_t *forward)
{
    int ins_num = 0;
    int index = ulIndex + 1;

    if ((index > g_Dns_ForwardCount) || (index < 1))
    {
        return -1;
    }

    Utopia_GetIndexedInt(ctx, UtopiaValue_Dns_Forward_InsNum, index, &ins_num);
    forward->ins_num = ins_num;
    Utopia_GetIndexed(ctx, UtopiaValue_Dns_Forward_Alias, index, forward->alias, sizeof(forward->alias));
    Utopia_GetIndexedBool(ctx, UtopiaValue_Dns_Forward_Enable, index, &forward->enable);
    Utopia_GetIndexed(ctx, UtopiaValue_Dns_Forward_IPAddress, index, forward->ip_address, sizeof(forward->ip_address));
    Utopia_GetIndexed(ctx, UtopiaValue_Dns_Forward_Interface, index, forward->interface, sizeof(forward->interface));
    Utopia_GetIndexed(ctx, UtopiaValue_Dns_Forward_Type, index, forward->type, sizeof(forward->type));

    return 0;
}

int Utopia_SetDnsForwardByIndex(UtopiaContext *ctx, unsigned long ulIndex, const relay_forward_t *forward)
{
    int index = ulIndex + 1;

    if ((index > g_Dns_ForwardCount) || (index < 1))
    {
        return -1;
    }

    snprintf(s_tokenbuf, sizeof(s_tokenbuf), "dns_forward_%d", index);
    Utopia_SetIndexed(ctx, UtopiaValue_Dns_Forward, index, s_tokenbuf);

    Utopia_SetIndexedInt(ctx, UtopiaValue_Dns_Forward_InsNum, index, forward->ins_num);
    Utopia_SetIndexed(ctx, UtopiaValue_Dns_Forward_Alias, index, (char*)forward->alias);
    Utopia_SetIndexedBool(ctx, UtopiaValue_Dns_Forward_Enable, index, forward->enable);
    Utopia_SetIndexed(ctx, UtopiaValue_Dns_Forward_IPAddress, index, (char*)forward->ip_address);
    Utopia_SetIndexed(ctx, UtopiaValue_Dns_Forward_Interface, index, (char*)forward->interface);
    Utopia_SetIndexed(ctx, UtopiaValue_Dns_Forward_Type, index, (char*)forward->type);

    return 0;
}

int Utopia_GetDnsForwardInsNumByIndex(UtopiaContext *ctx, unsigned long ulIndex, int *ins)
{
    return Utopia_GetIndexedInt(ctx, UtopiaValue_Dns_Forward_InsNum, ulIndex + 1, ins);
}

int Utopia_GetDnsForwardIndexByInsNum(UtopiaContext *ctx, int ins, unsigned long *ulIndex)
{
    int i = 0;
    int ins_num = 0;

    for (; i < g_Dns_ForwardCount; i++)
    {
        Utopia_GetDnsForwardInsNumByIndex(ctx, i, &ins_num);
        if (ins_num == ins) {
            *ulIndex = i;
            return 0;
        }
    }

    return -1;
}

int Utopia_AddDnsForward(UtopiaContext *ctx, const relay_forward_t *forward)
{
    int count = Utopia_GetNumberOfDnsForwards(ctx);
    Utopia_SetInt(ctx, UtopiaValue_Dns_ForwardCount, ++g_Dns_ForwardCount);
    Utopia_SetDnsForwardByIndex(ctx, count, forward);

    return 0;
}

int Utopia_RemoveDnsForward(UtopiaContext *ctx, unsigned long ins)
{
    int count = 0;
    int index = 0;

    count = Utopia_GetNumberOfDnsForwards(ctx);
    for (; index < count; index++)
    {
        int ins_num = 0;
        Utopia_GetDnsForwardInsNumByIndex(ctx, index, &ins_num);
        if (ins_num == (int)ins)
        {
            break;
        }
    }

    if (index >= count)
    {
        return -1;
    }

    if (index < count - 1)
    {
        for (; index < count - 1; index++)
        {
            relay_forward_t dns = {};
            Utopia_GetDnsForwardByIndex(ctx, index + 1, &dns);
            Utopia_SetDnsForwardByIndex(ctx, index, &dns);
        }
    }

    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_Forward_InsNum, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_Forward_Alias, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_Forward_Enable, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_Forward_IPAddress, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_Forward_Interface, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_Forward_Type, count);
    Utopia_UnsetIndexed(ctx, UtopiaValue_Dns_Forward, count);

    g_Dns_ForwardCount--;
    Utopia_SetInt(ctx, UtopiaValue_Dns_ForwardCount, g_Dns_ForwardCount);

    return 0;
}

int Utopia_GetDnsRelayEnabled(UtopiaContext *ctx, boolean_t *enabled)
{
    return Utopia_GetBool(ctx, UtopiaValue_Dns_Relay_Enable, enabled);
}

int Utopia_SetDnsRelayEnabled(UtopiaContext *ctx, boolean_t enabled)
{
    return Utopia_SetBool(ctx, UtopiaValue_Dns_Relay_Enable, enabled);
}
