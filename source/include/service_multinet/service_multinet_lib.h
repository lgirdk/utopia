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
   Copyright [2015] [Cisco Systems, Inc.]
 
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
#ifndef MNET_LIB_H
 #define MNET_LIB_H
 
 #include "service_multinet_base.h"

 
 #define MAX_MEMBERS 32
 
 extern unsigned char isDaemon;
 extern char* executableName;
 
 int multinet_bridgeUp(PL2Net network, int bFirewallRestart);
 int multinet_bridgeUpInst(int l2netInst, int bFirewallRestart);
 
 int multinet_bridgeDown(PL2Net network);
 int multinet_bridgeDownInst(int l2netInst);
 
 int multinet_Sync(PL2Net network, PMember members, int numMembers);
 int multinet_SyncInst(int l2netInst);
 
 int multinet_bridgesSync();
 
 int multinet_ifStatusUpdate(PL2Net network, PMember interface, IF_STATUS status);
 int multinet_ifStatusUpdate_ids(int l2netInst, char* ifname, char* ifType, char* status, char* tagging);
 
 int multinet_lib_init(BOOL daemon, char* exeName);

#if defined(MULTILAN_FEATURE)
 int multinet_assignBridgeCIDR(int l2netInst, char *CIDR, int IPVersion);
 int multinet_setBridgePortsMTU(int l2netInst, int MTU);
#endif
 
 #endif
