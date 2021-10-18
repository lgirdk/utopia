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

const char* SERVICE_NAME            = "hotspot";
const char* SERVICE_DEFAULT_HANDLER = "/etc/utopia/service.d/service_multinet/handle_gre.sh";
const char* SERVICE_CUSTOM_EVENTS[] = { 
                                        "gre-restart|/etc/utopia/service.d/service_multinet/handle_gre.sh|"ACTION_FLAG_COLLAPSE_PENDING_QUEUE"|"TUPLE_FLAG_EVENT,
                                        "gre-forceRestart|/etc/utopia/service.d/service_multinet/handle_gre.sh|"ACTION_FLAG_COLLAPSE_PENDING_QUEUE"|"TUPLE_FLAG_EVENT,
                                        "snmp_subagent-status|/etc/utopia/service.d/service_multinet/handle_gre.sh",
                                        "hotspot-update_bridges|/etc/utopia/service.d/service_multinet/handle_gre.sh|"ACTION_FLAG_COLLAPSE_PENDING_QUEUE"|"TUPLE_FLAG_EVENT,
                                        "hotspot-restart|/etc/utopia/service.d/service_multinet/handle_gre.sh|"ACTION_FLAG_COLLAPSE_PENDING_QUEUE"|"TUPLE_FLAG_EVENT,
#if defined (COMMUNITY_WIFI_ENABLE)
                                        "update-vlanID|/etc/utopia/service.d/service_multinet/handle_gre.sh|"ACTION_FLAG_COLLAPSE_PENDING_QUEUE"|"TUPLE_FLAG_EVENT,
#endif
                                        NULL
                                      };

void srv_register(void) {
   sm_register(SERVICE_NAME, SERVICE_DEFAULT_HANDLER, SERVICE_CUSTOM_EVENTS);
   system("modprobe brMtuMod");
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

