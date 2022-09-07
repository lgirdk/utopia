#!/bin/sh

####################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
#  Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##################################################################################

source /etc/device.properties

getWanInterfaceName()
{
  interface_name=`sysevent get current_wan_ifname`
  if [ -z "$interface_name" ];then
      interface_name="erouter0"
  fi
  echo "$interface_name"
}
getWanMacInterfaceName()
{
  if [ "x$rdkb_extender" = "xtrue" ];then
        mac_interface="eth0"
  else
    mac_interface=`syscfg get wan_physical_ifname`
    if [ -z "$mac_interface" ];then
        mac_interface="erouter0"
    fi  
  fi
  echo "$mac_interface"
}
