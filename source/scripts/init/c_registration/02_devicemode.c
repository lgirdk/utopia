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
#include "srvmgr.h"
#include <string.h>
#include <stdlib.h>

const char* SERVICE_NAME            = "devicemode";
const char* SERVICE_DEFAULT_HANDLER = "/etc/utopia/service.d/service_devicemode/service_devicemode.sh";
const char* SERVICE_CUSTOM_EVENTS[] = { 
     "DeviceMode|/etc/utopia/service.d/service_devicemode/service_devicemode.sh|NULL|"TUPLE_FLAG_EVENT,
   //  "wan-status|/etc/utopia/service.d/service_devicemode/service_devicemode.sh|NULL|"TUPLE_FLAG_EVENT,
     "mesh_wan_linkstatus|/etc/utopia/service.d/service_devicemode/service_devicemode.sh",
     "ipv6_nameserver|/etc/utopia/service.d/service_devicemode/service_devicemode.sh|NULL|"TUPLE_FLAG_EVENT,
      "ipv4_nameserver|/etc/utopia/service.d/service_devicemode/service_devicemode.sh|NULL|"TUPLE_FLAG_EVENT,
     "cellular_wan_v4_ip|/etc/utopia/service.d/service_devicemode/service_devicemode.sh|NULL|"TUPLE_FLAG_EVENT,
     "cellular_wan_v6_ip|/etc/utopia/service.d/service_devicemode/service_devicemode.sh|NULL|"TUPLE_FLAG_EVENT,
     "dummy_route|/etc/utopia/service.d/service_devicemode/service_devicemode.sh|NULL|"TUPLE_FLAG_EVENT,
      "correct_dns_route|/etc/utopia/service.d/service_devicemode/service_devicemode.sh|NULL|"TUPLE_FLAG_EVENT,
      "correct_resolve_conf|/etc/utopia/service.d/service_devicemode/service_devicemode.sh|NULL|"TUPLE_FLAG_EVENT,

    NULL };

void srv_register(void) {
   sm_register(SERVICE_NAME, SERVICE_DEFAULT_HANDLER, SERVICE_CUSTOM_EVENTS);
   system("sysevent set dummy_route");
}

void srv_unregister(void) {
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
