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
#ifdef RDKB_EXTENDER_ENABLED
#include <string.h>
#endif
#include "srvmgr.h"

const char* SERVICE_NAME            = "dhcp_server";
const char* SERVICE_DEFAULT_HANDLER = "/etc/utopia/service.d/service_dhcp_server.sh";
#if defined(_COSA_INTEL_USG_ARM_) && !defined(INTEL_PUMA7) && !defined(_COSA_BCM_ARM_) && !defined(_PLATFORM_IPQ_) && !defined(_PLATFORM_TURRIS_)
const char* SERVICE_CUSTOM_EVENTS[] = { 
                                        "syslog-status|/etc/utopia/service.d/service_dhcp_server.sh",
                                        "lan-status|/usr/bin/service_dhcp",
										"dhcp_server-restart|/usr/bin/service_dhcp",
                                        "dhcp_server-start|/usr/bin/service_dhcp",
                                        "dhcp_server-stop|/usr/bin/service_dhcp",
                                        "dhcp_server-resync|/etc/utopia/service.d/service_dhcp_server.sh|NULL|"TUPLE_FLAG_EVENT,
                                        NULL 
                                      };
#elif defined(CORE_NET_LIB) && \
        ((defined(_XB6_PRODUCT_REQ_) && !defined (_XB8_PRODUCT_REQ_)) || \
         (defined(_CBR_PRODUCT_REQ_) && !defined(_CBR2_PRODUCT_REQ_)))
const char* SERVICE_CUSTOM_EVENTS[] = {
                                        "syslog-status|/usr/bin/service_dhcp",
                                        "lan-status|/usr/bin/service_dhcp",
                                        "dhcp_server-restart|/usr/bin/service_dhcp|NULL|"TUPLE_FLAG_EVENT,
                                        "dhcp_server-start|/usr/bin/service_dhcp|NULL|"TUPLE_FLAG_EVENT,
                                        "dhcp_server-stop|/usr/bin/service_dhcp|NULL|"TUPLE_FLAG_EVENT,
                                        "dhcp_server-resync|/usr/bin/service_dhcp|NULL|"TUPLE_FLAG_EVENT,
                                        NULL 
                                      };
#else
const char* SERVICE_CUSTOM_EVENTS[] = { 
                                        "syslog-status|/etc/utopia/service.d/service_dhcp_server.sh",
                                        "lan-status|/etc/utopia/service.d/service_dhcp_server.sh",
                                        "dhcp_server-resync|/etc/utopia/service.d/service_dhcp_server.sh|NULL|"TUPLE_FLAG_EVENT,
                                        NULL 
                                      };
#endif

void srv_register(void) {
   sm_register(SERVICE_NAME, SERVICE_DEFAULT_HANDLER, SERVICE_CUSTOM_EVENTS);
   system ("/etc/utopia/service.d/pmon.sh register dhcp_server");
}

#ifdef RDKB_EXTENDER_ENABLED
int getcustomServiceFile(char *event,char *out,int outlen)
{
    int retvalue = -1;
    int index = 0;    
    while (SERVICE_CUSTOM_EVENTS[index] != NULL)
    {
        char eventname[128];
        char *pEnd = strstr(SERVICE_CUSTOM_EVENTS[index],"|");
        if (!pEnd)
        {
            ++index;
            continue;
        }
        memset(eventname,0,sizeof(eventname));
        if ((pEnd-SERVICE_CUSTOM_EVENTS[index]) < sizeof(eventname))
        {
            memcpy(eventname,SERVICE_CUSTOM_EVENTS[index],pEnd-SERVICE_CUSTOM_EVENTS[index]);
        }
        if (!strcmp(event,eventname))
        {
            char *pServiceFile = pEnd + 1;
            pEnd =  strstr(pServiceFile,"|");  
            if (pEnd == NULL )
            {
                memcpy(out,pServiceFile,strlen(pServiceFile));
                return 0;
            }
            else if((pEnd-pServiceFile) < outlen)
            {
                memcpy(out,pServiceFile,pEnd-pServiceFile);
                return 0;
            }
        }
        ++index;
    }
    return retvalue;
}

void stop_service()
{
    char buf[512];
    char serviceFile[256];
    int retvalue = -1;
    
    memset(buf,0,sizeof(buf));
    memset(serviceFile,0,sizeof(serviceFile));
    snprintf(buf,sizeof(buf),"%s-stop",SERVICE_NAME);
    retvalue = getcustomServiceFile(buf,serviceFile,sizeof(serviceFile));
    memset(buf,0,sizeof(buf));
    //found custom service file
    if (retvalue == 0)
    {
        snprintf(buf,sizeof(buf),"sh %s %s-stop",serviceFile,SERVICE_NAME);

    }
    else // not found.
    {
        snprintf(buf,sizeof(buf),"sh %s %s-stop",SERVICE_DEFAULT_HANDLER,SERVICE_NAME);
    }
    system(buf);
}
#endif

void srv_unregister(void) {
   system ("/etc/utopia/service.d/pmon.sh unregister dhcp_server");
   #ifdef RDKB_EXTENDER_ENABLED
   stop_service();
   #endif
   sm_unregister(SERVICE_NAME);
}

int main(int argc, char **argv)
{
   cmd_type_t choice = parse_cmd_line(argc, argv);

   switch(choice) {
      case(nochoice):
      case(start):
         srv_register();
         break;
      case(stop):
         srv_unregister();
         break;
      case(restart):
         srv_unregister();
         srv_register();
         break;
      default:
         printf("%s called with invalid parameter (%s)\n", argv[0], 1==argc ? "" : argv[1]);
   }
   return(0);
}
