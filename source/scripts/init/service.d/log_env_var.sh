#!/bin/sh

##################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:

#  Copyright 2018 RDK Management

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################
NVRAM2_SUPPORTED="no"
ATOM_IP=""
UPLOAD_THRESHOLD=""

TMP_UPLOAD="/tmp/logs/"
LOG_SYNC_PATH="/nvram2/logs/"
LOG_SYNC_BACK_UP_PATH="/nvram2/logs/"
LOG_SYNC_BACK_UP_REBOOT_PATH="/nvram2/logs/"

. /etc/device.properties

LOG_FOLDER="/rdklogs"
LOG_UPLOAD_FOLDER="/tmp"
RDK_LOGGER_PATH="/rdklogger"
LOG_PATH="$LOG_FOLDER/logs/"
TMP_LOG_PATH="$LOG_UPLOAD_FOLDER/logs/"
ATOM_LOG_PATH="/rdklogs/logs/"

#dmesg sync
DMESG_FILE="/rdklogs/logs/messages.txt"
lastdmesgsync="/tmp/lastdmesgsynctime"
journal_log="/rdklogs/logs/journal_logs.txt.0"

LOG_BACK_UP_PATH="$LOG_UPLOAD_FOLDER/logbackup/"
LOGTEMPPATH="$LOG_FOLDER/backuplogs/"
LOG_BACK_UP_REBOOT="$LOG_UPLOAD_FOLDER/logbackupreboot/"

HAVECRASH="$LOG_FOLDER/processcrashed"
FLAG_REBOOT="$LOG_FOLDER/waitingreboot"
UPLOAD_ON_REBOOT="$LOG_UPLOAD_FOLDER/uploadonreboot"
LOG_UPLOAD_ON_REQUEST="$LOG_UPLOAD_FOLDER/loguploadonrequest/"

UPLOAD_ON_REQUEST="$LOG_FOLDER/uploadingonrequest"
UPLOAD_ON_REQUEST_SUCCESS="$LOG_UPLOAD_FOLDER/uploadsuccess"
REGULAR_UPLOAD="$LOG_FOLDER/uploading"

UPLOADRESULT="$LOG_UPLOAD_FOLDER/resultOfupload"
WAN_INTERFACE="erouter0"
OutputFile="/tmp/httpresult.txt"
HTTP_CODE="/tmp/curl_httpcode"
S3_URL="https://ssr.ccp.xcal.tv/cgi-bin/rdkb_snmp.cgi"
WAITINGFORUPLOAD="$LOG_UPLOAD_FOLDER/waitingforupload"

MAXLINESIZE=2

#Devices that have more nvram size can override default upload threshold (1.5MB) through device.properties
if [ -n "$LOG_UPLOAD_THRESHOLD" ]
then
	MAXSIZE=$LOG_UPLOAD_THRESHOLD
else
	MAXSIZE=1536
fi    

if [ -z $LOG_PATH ]; then
    LOG_PATH="$LOG_FOLDER/logs/"
fi

if [ -z "$PERSISTENT_PATH" ]; then
    PERSISTENT_PATH="/tmp"
fi

LOG_FILE_FLAG="$LOG_FOLDER/filescreated"

if [ "$BOX_TYPE" = "XB3" ] || [ "$BOX_TYPE" = "MV1" ];then
    CONSOLEFILE="$LOG_FOLDER/logs/ArmConsolelog.txt.0"
else
    CONSOLEFILE="$LOG_FOLDER/logs/Consolelog.txt.0"
fi

SELFHEALFILE="$LOG_FOLDER/logs/SelfHeal.txt.0"
SELFHEALFILE_BOOTUP="$LOG_SYNC_PATH/SelfHealBootUp.txt.0"

lockdir=$LOG_FOLDER/rxtx

DCMRESPONSE="/nvram/DCMresponse.txt"
DCMRESPONSE_TMP="/tmp/DCMresponse.txt"
DCM_SETTINGS_PARSED="/tmp/DCMSettingsParsedForLogUpload"

TMP_LOG_UPLOAD_PATH="/tmp/log_upload"

RAM_OOPS_FILE_LOCATION="/sys/fs/pstore/"
RAM_OOPS_FILE="*-ramoops*"
RAM_OOPS_FILE0="dmesg-ramoops-0"
RAM_OOPS_FILE0_HOST="dmesg-ramoops-0_host"
RAM_OOPS_FILE1="dmesg-ramoops-1"
RAM_OOPS_FILE1_HOST="dmesg-ramoops-1_host"
