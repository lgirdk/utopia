#!/bin/sh

SERVER4_CONF="$1"
SERVER6_CONF="/etc/dibbler/server.conf"
SERVER6_CONF_BKUP="/etc/dibbler/server_bkp.conf"
RESOLV_CONF="/etc/resolv.conf"

# FirstInstallWizard_Enable : Device.X_LGI-COM_General.FirstInstallWizardEnable
# FirstInstall_State        : Device.X_LGI-COM_General.FirstInstallState
# CaptivePortal_Enable      : Device.X_LGI-COM_General.FirstInstallRedirectAll
# cloud_enable_flag         : Device.X_LGI-COM_General.CloudUIEnable
# redirection_url           : Device.X_LGI-COM_General.CloudUIUrl

FirstInstall_Enable=$(syscfg get FirstInstallWizard_Enable)
FirstInstall_State=$(syscfg get FirstInstall_State)
Redirection_Enable=$(syscfg get CaptivePortal_Enable)

[ "$FirstInstall_State" != "false" ] && FirstInstall_State="true"

if [ "$FirstInstall_Enable" = "true" ] && [ "$FirstInstall_State" = "true" ] && [ "$Redirection_Enable" = "true" ]
then
	echo 'FirstInstall: Redirection'
	# Modify DNS server option in dnsmasq configuration
	if [ -e $SERVER4_CONF ]
	then
		sed '/resolv-file/s/^/#/; /dhcp-optsfile/s/^/#/' -i $SERVER4_CONF
		echo "no-poll" >> $SERVER4_CONF
		echo "no-resolv" >> $SERVER4_CONF

		# FirstInstall: Redirection Whitelist
		Cloud_Enable=$(syscfg get cloud_enable_flag)
		if [ "$Cloud_Enable" = "1" ]
		then
			# Warning: syscfg string may be single quoted
			Cloud_URL=$(syscfg get redirection_url | tr -d \')
			if [ -n "$Cloud_URL" ] && [ "$Cloud_URL" != 'http://127.0.0.1' ]
			then
				echo 'FirstInstall: Redirection Whitelist'
				WHITELIST_URL=$(echo $Cloud_URL | cut -f2 -d":" | cut -f3 -d"/")
				nServer4=$(grep nameserver $RESOLV_CONF | grep "\." | tail -n1 | cut -d" " -f2)
				echo "server=/$WHITELIST_URL/$nServer4" >> $SERVER4_CONF
			fi
		else
			echo 'FirstInstall: Revert Redirection Whitelist'
			sed '/server=/d' -i $SERVER4_CONF
		fi

		HTTP_Server_IP=$(syscfg get HTTP_Server_I)
		DnsmasqIP_Option="address=/#/${HTTP_Server_IP}"
		echo $DnsmasqIP_Option >> $SERVER4_CONF
	else
		echo "No dnsmasq configuration available...."
	fi

	# DHCPv6 Server will only be available in DSLite and DualStack mode
	# Modify DNS server option in dibbler configuration if applicable
	if [ -e $SERVER6_CONF ] && [ ! -e $SERVER6_CONF_BKUP ]
	then
		cp -f $SERVER6_CONF $SERVER6_CONF_BKUP
		sed '/dns-server/s/^/#/' -i $SERVER6_CONF
		dibbler-server stop
		sleep 2
		dibbler-server start
	else
		echo "No dibbler configuration available for V6...."
	fi

	sysevent set firewall-restart
	/bin/sh /etc/start_lighttpd.sh restart

else
	echo 'FirstInstall: Revert Redirection'
	if [ -e $SERVER6_CONF_BKUP ]
	then
		cp -f $SERVER6_CONF_BKUP $SERVER6_CONF
		rm -f $SERVER6_CONF_BKUP
		dibbler-server stop
		sleep 2
		dibbler-server start
		sysevent set firewall-restart
		/bin/sh /etc/start_lighttpd.sh restart
	fi
fi
