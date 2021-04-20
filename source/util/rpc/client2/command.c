/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include "rpc_client.h"
#include "rpc_specification.h"
#include "pthread.h"

#define ARM_ARPING_IP "192.168.254.253"
#define ATOM_ARPING_IP "192.168.254.254"

int ExecuteCommand(char *cmnd)
{
	CLIENT *clnt = NULL;
	struct rpc_CommandBuf commandBuf;
	struct rpc_CommandBuf *output = NULL;
	strncpy(commandBuf.buffer,cmnd,sizeof(commandBuf.buffer)-1);
	commandBuf.buffer[sizeof(commandBuf.buffer)-1] = '\0';
	char* errStr;
	/*bool isconnected = getIsconnectedStatus();
	if(!isconnected) {	
		//startRPCThread();
		return 0;
	}*/
	clnt = getClientInstance();  
	if(clnt != NULL) {
		output=executecommand_1(&commandBuf,clnt);
		if(output == NULL){
			errStr = clnt_sperror(clnt,"RPC");
			if(isRPCConnectionLoss(errStr))
			return 0;
		}
	}
 
	 if(output != NULL) {
	 	printf("\n%s\n",output->buffer);
	 } else {
	 	printf("ATOM CONSOLE OUTPUT IS NULL\n");
	 }

	return 1;

}

int ExeSysCmd(char *cmnd)
{
	CLIENT *clnt = NULL;
        struct rpc_CommandBuf commandBuf;
	/* CID 135428: Unbounded source buffer*/
	strncpy(commandBuf.buffer,cmnd,sizeof(commandBuf.buffer)-1);
	commandBuf.buffer[sizeof(commandBuf.buffer)-1] = '\0';
        char* errStr;	
	int *output = NULL;

	clnt = getClientInstance();
        if(clnt != NULL) {

                output = exec_1(&commandBuf,clnt);
                if(output == NULL){
                        errStr = clnt_sperror(clnt,"RPC");
                        if(isRPCConnectionLoss(errStr))
                        return 0;
                }
        }
	return 1;
}

int
main (int argc, char *argv[],char **args)
{
    int iRet;
#ifdef _COSA_INTEL_USG_ATOM_
    char *l_cArpingIP = ARM_ARPING_IP;
#elif _COSA_INTEL_USG_ARM_
    char *l_cArpingIP = ATOM_ARPING_IP;
#else
#error "Unexpected platform"
#endif            

    if (argc < 2) {
        printf("usage example: %s ls\n",argv[0]);
        exit(0);
    }

    iRet = initRPC(l_cArpingIP);
    if(iRet == 1) 
    {
        if(strcmp(argv[1],"sh") == 0)
        {
            if(argv[2] != NULL) 
                iRet = ExeSysCmd(argv[2]);
            else
                iRet = ExecuteCommand(argv[1]);
            
            if(iRet == 0) {
                printf("RPC FAILED while executing the command:%s !!!\n", argv[1]);
            }
            exit(0);
        }
        iRet = ExecuteCommand(argv[1]);
        if(iRet == 0) {
            printf("RPC FAILED while executing the command:%s !!!\n", argv[1]);
        }
        exit(0);
    }
    else
    {
        printf("RPC FAILED while opening socket !!!\n");
        exit(0);
    }  
    exit(1);
}
