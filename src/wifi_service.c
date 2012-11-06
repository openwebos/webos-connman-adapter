/* @@@LICENSE
*
*      Copyright (c) 2012 Hewlett-Packard Development Company, L.P.
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
*
* LICENSE@@@ */

/**
 * @file  wifi_service.c
 *
 * @brief Implements all of the com.palm.wifi methods using connman APIs
 * in the backend
 *
 */


#include <glib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <pbnjson.h>

#include "wifi_service.h"
#include "connman_manager.h"
#include "lunaservice_utils.h"


bool handle_get_profile_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_get_info_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_connect_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_set_state_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_scan_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_delete_profile_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_get_status_command(LSHandle* sh, LSMessage *message, void* context);

/**
 * com.palm.wifi service Luna Method Table
 */

LSMethod wifi_methods[] = {
    { LUNA_METHOD_GETPROFILELIST,	handle_get_profile_command },
    { LUNA_METHOD_GETPROFILE,		handle_get_profile_command },
    { LUNA_METHOD_GETINFO,		handle_get_info_command },
    { LUNA_METHOD_SETSTATE,		handle_set_state_command },
    { LUNA_METHOD_CONNECT,		handle_connect_command },
    { LUNA_METHOD_FINDNETWORKS,		handle_scan_command },
    { LUNA_METHOD_DELETEPROFILE,	handle_delete_profile_command },
    { LUNA_METHOD_GETSTATUS,		handle_get_status_command },
    { },
};

LSHandle *pLsHandle;
LSHandle *pLsPublicHandle;

connman_manager_t *manager = NULL;

/* Constant for mapping access point signal strength to signal levels ( 1 to 5) */
#define MAX_SIGNAL_BARS         5

/**
 *  @brief Returns true if wifi technology is powered on
 *  
 */

gboolean is_wifi_powered(void)
{
	connman_technology_t *technology = connman_manager_find_wifi_technology(manager);
	return technology->powered;
}

/**
 *  @brief Sets the wifi technologies powered state
 *  
 *  @param state
 */

gboolean set_wifi_state(bool state)
{
	return connman_technology_set_powered(connman_manager_find_wifi_technology(manager),state);
}

/**
 *  @brief Check if the wifi technology is available
 *   Send a luna message if its not available
 *
 *  @param sh
 *  @param message
 */

gboolean wifi_technology_status_check(LSHandle *sh, LSMessage *message)
{
	if(!connman_manager_find_wifi_technology(manager))
	{
		LSMessageReplyCustomError(sh, message, "WiFi technology unavailable");
		return false;
	}
	return true;
}

/**
 *  @brief Check if the connman manager is not in offline mode
 *   Send a luna message if it is
 *
 *  @param sh
 *  @param message
 */


gboolean connman_status_check(LSHandle *sh, LSMessage *message)
{
	if(!connman_manager_is_manager_available(manager))
	{
		LSMessageReplyCustomError(sh, message, "Connman service unavailable");
		return false;
	}
	return true;
}

/**
 *  @brief Handler for "setstate" command.
 *  Enable/disable the wifi service
 *  
 *  JSON format:
 *  luna://com.palm.wifi/setstate {"state":"enabled"}
 *  
 *  @param sh
 *  @param message
 *  @param context
 *
 */

bool handle_set_state_command(LSHandle *sh, LSMessage *message, void* context)
{
	if(!connman_status_check(sh, message))
		return true;

	if(!wifi_technology_status_check(sh, message))
		return true;

	jvalue_ref parsedObj = {0};
	jschema_ref input_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(!input_schema)
		return false;

    	JSchemaInfo schemaInfo;
    	jschema_info_init(&schemaInfo, input_schema, NULL, NULL); // no external refs & no error handlers
    	parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)), DOMOPT_NOOPT, &schemaInfo);
    	jschema_release(&input_schema);

	if (jis_null(parsedObj)) {
        	LSMessageReplyErrorBadJSON(sh, message);
        	goto cleanup;
    	}


	jvalue_ref stateObj = {0};
	gboolean enable_wifi = FALSE;
	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("state"), &stateObj))
	{
		if (jstring_equal2(stateObj, J_CSTR_TO_BUF("enabled")))
		{
			enable_wifi = TRUE;
		}
		else if (jstring_equal2(stateObj, J_CSTR_TO_BUF("disabled")))
		{
			enable_wifi = FALSE;

		}
		else
		{
        		LSMessageReplyErrorBadJSON(sh, message);
        		goto cleanup;
		}		
	}

	/*
	 *  Check if we are enabling an already enabled service, 
	 *  or disabling an already disabled service
	 */

	if(enable_wifi && is_wifi_powered()) 
	{
		LSMessageReplyCustomError(sh, message, "Already Enabled");
		goto cleanup;
	}
	else if(!enable_wifi && !is_wifi_powered())
	{
		LSMessageReplyCustomError(sh, message, "Already Disabled");
		goto cleanup;
	}

	set_wifi_state(enable_wifi);
	
	LSMessageReplySuccess(sh,message);

cleanup:
	j_release(&parsedObj);
	return true;

}

/**
 *  @brief Connect to a access point with the given ssid
 *
 *  @param ssid 
 */

bool connect_wifi_with_ssid(const char *ssid)
{
 	GSList *ap;

	/* Look up for the service with the given ssid */
        for (ap = manager->services; ap; ap = ap->next)
        {
                connman_service_t *service = (connman_service_t *)(ap->data);
		if(g_str_equal(service->name, ssid)) 
		{               
			g_message("ssid %s found, now connecting",service->name);
			connman_service_t *connected_service = connman_manager_get_connected_service(manager);
			if((connected_service != NULL) && (connected_service != service)) 
			{
				connman_service_disconnect(connected_service);
			}
			
			if(connman_service_connect(service))
			{
				return true;
			}					
			else
			{
				g_message("Error in connecting");
				return false;
			}		
		}
        }
	return false;
}


/**
 *  @brief Handler for "connect" command.
 *  Connect to a wifi access point with its ssid or its profile Id 
 *  
 *  JSON format:
 *  luna://com.palm.wifi/connect '{"ssid":"<Name of the access point>"}'
 *  luna://com.palm.wifi/connect '{"profileId":<Profile ID>}'`
 * 
 *  @param sh
 *  @param message
 *  @param context
 *
 */

bool handle_connect_command(LSHandle *sh, LSMessage *message, void* context)
{
	if(!connman_status_check(sh, message))
		return true;

	if(!wifi_technology_status_check(sh, message))
		return true;

        if(!is_wifi_powered()) {
                LSMessageReplyCustomError(sh,message,"WiFi switched off");
		return true;
	}

	/* Update services in case the "services_changed" signal was triggered
	 * which will happen if a new service was added, or existing service
	 * was modified, or a service was removed 
         */
	connman_manager_update_services(manager);

	jvalue_ref parsedObj = {0};
        jschema_ref input_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
        if(!input_schema)
                return false;

        JSchemaInfo schemaInfo;
        jschema_info_init(&schemaInfo, input_schema, NULL, NULL); // no external refs & no error handlers
        parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)), DOMOPT_NOOPT, &schemaInfo);
        jschema_release(&input_schema);

        if (jis_null(parsedObj)) {
                LSMessageReplyErrorBadJSON(sh, message);
                goto cleanup;
        }


        jvalue_ref ssidObj = {0};

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer ssid_buf = jstring_get(ssidObj);
		char *ssid = g_strdup(ssid_buf.m_str);
		if(connect_wifi_with_ssid(ssid))
                        LSMessageReplySuccess(sh, message);
                else
                        LSMessageReplyErrorUnknown(sh, message);
		g_free(ssid);
	}

cleanup:
	j_release(&parsedObj);
	return true;
}

/**  @brief Add details about the given service representing a wifi access point
 *  
 *  @param service
 *  @param network
 *
 */
 
void add_service(connman_service_t *service, jvalue_ref *network)
{
	if(service->name != NULL)	
		jobject_put(*network, J_CSTR_TO_JVAL("ssid"), jstring_create(service->name));

	if((service->security != NULL) && g_strv_length(service->security))
	{
		gsize i;
		jvalue_ref security_list = jarray_create(NULL);
		for (i = 0; i < g_strv_length(service->security); i++)
		{
			jarray_append(security_list, jstring_create(service->security[i]));
		}
		jobject_put(*network, J_CSTR_TO_JVAL("availableSecurityTypes"),security_list);
	}

	int signalbars = (service->strength * MAX_SIGNAL_BARS) / 100;

	jobject_put(*network, J_CSTR_TO_JVAL("signalBars"),jnumber_create_i32(signalbars));
	jobject_put(*network, J_CSTR_TO_JVAL("signalLevel"),jnumber_create_i32(service->strength));

	if(service->state != NULL) 
	{
		if(connman_service_get_state(service->state) != CONNMAN_SERVICE_STATE_IDLE)
		{
			jobject_put(*network, J_CSTR_TO_JVAL("connectState"),jstring_create(connman_service_get_webos_state(connman_service_get_state(service->state)))); 
		}
	}
}

/**
 *  @brief Populate information about all the found networks
 *
 *  @param sh
 *  @param message
 *
 */

void populate_wifi_networks(LSHandle *sh, LSMessage *message)
{
	bool networks_found = false;  
	LSError lserror;

	jvalue_ref reply = jobject_create();
	jvalue_ref network_list = jarray_create(NULL);

	GSList *ap;

	connman_manager_update_services(manager);

	/* Go through the manager's services list and fill in details 
	   for each one of them */
	
	for (ap = manager->services; ap; ap = ap->next)
	{
		jvalue_ref network = jobject_create();
		connman_service_t *service = (connman_service_t *)(ap->data);
		if(!connman_service_type_wifi(service) || (service->name == NULL))
			continue;
		add_service(service, &network);
		
		jvalue_ref network_list_j = jobject_create();
		jobject_put(network_list_j, J_CSTR_TO_JVAL("networkInfo"), network);
		jarray_append(network_list, network_list_j);
		
		networks_found = true;
        }

	if(networks_found)
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
		jobject_put(reply, J_CSTR_TO_JVAL("foundNetworks"), network_list);

		jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
		if(!response_schema) {
	                LSMessageReplyErrorUnknown(sh,message);
			return;
	    	}
		if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror)) {
		        LSErrorPrint(&lserror, stderr);
		        LSErrorFree(&lserror);
    		}
		jschema_release(&response_schema);
	}
	else
        	LSMessageReplySuccess(sh, message);
	
	j_release(&reply);
}

/**
 *  @brief Handler for "findnetworks" command.
 *  Scan for all the available access points and list their info like ssid name, 
 *  available security types, signal strength, connection status
 *  
 *  JSON format:
 *  luna://com.palm.wifi/findnetworks {}
 *  luna://com.palm.wifi/findnetworks {"subscribe":true}
 *  
 *  @param sh
 *  @param message
 *  @param context
 *
 */

bool handle_scan_command(LSHandle *sh, LSMessage *message, void* context)
{
	if(!connman_status_check(sh, message))
		goto cleanup;

	if(!wifi_technology_status_check(sh, message))
		goto cleanup;

	if(!is_wifi_powered())
	{
		LSMessageReplyCustomError(sh,message,"WiFi switched off");
		goto cleanup;
	}

	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);
        if(wifi_tech == NULL)
        {
                LSMessageReplySuccess(sh, message);
                goto cleanup;
        }

	/* Scan the network for all available access points by making a connman call*/
        connman_technology_scan_network(wifi_tech);

	/* Fill in details of all the found wifi networks */
	populate_wifi_networks(sh, message);	
cleanup:
	return true;
}

 /**
  *  @brief Add details about the connected service
  * 
  *  @param reply
  *  @param connected_service
  *
  */

void add_connected_network_status(jvalue_ref *reply, connman_service_t *connected_service)
{
	int connman_state = 0;
	jobject_put(*reply, J_CSTR_TO_JVAL("status"), jstring_create("connectionStateChanged"));

    	jvalue_ref network_info = jobject_create();	

	/* Fill in details about the service access point */
	if(connected_service->name != NULL)
		jobject_put(network_info, J_CSTR_TO_JVAL("ssid"), jstring_create(connected_service->name));

	if(connected_service->state != NULL)
	{
		connman_state = connman_service_get_state(connected_service->state);
		jobject_put(network_info, J_CSTR_TO_JVAL("connectState"), jstring_create(connman_service_get_webos_state(connman_state)));
	}

	jobject_put(network_info, J_CSTR_TO_JVAL("signalBars"), jnumber_create_i32((connected_service->strength * MAX_SIGNAL_BARS) / 100)); 
	jobject_put(network_info, J_CSTR_TO_JVAL("signalLevel"), jnumber_create_i32(connected_service->strength)); 
	
	jobject_put(*reply,  J_CSTR_TO_JVAL("networkInfo"), network_info);

	/* Fill in ip information only for a service which is online (fully connected) */
	if(connman_state == CONNMAN_SERVICE_STATE_ONLINE)
	{
		connman_service_get_ipinfo(connected_service);
		jvalue_ref ip_info = jobject_create();	

		jobject_put(ip_info, J_CSTR_TO_JVAL("interface"), jstring_create(connected_service->ipinfo.iface));
		jobject_put(ip_info, J_CSTR_TO_JVAL("ip"), jstring_create(connected_service->ipinfo.address));
		jobject_put(ip_info, J_CSTR_TO_JVAL("subnet"), jstring_create(connected_service->ipinfo.netmask));
		jobject_put(ip_info, J_CSTR_TO_JVAL("gateway"), jstring_create(connected_service->ipinfo.gateway));

		gsize i;
		char dns_str[16];
		for (i = 0; i < g_strv_length(connected_service->ipinfo.dns); i++)
		{
			sprintf(dns_str,"dns%d",i+1);
			jobject_put(ip_info, jstring_create(dns_str), jstring_create(connected_service->ipinfo.dns[i]));
		}

		jobject_put(*reply,  J_CSTR_TO_JVAL("ipInfo"), ip_info);
        }
}


/**
 *  @brief Handler for "getstatus" command.
 *  Get the current wifi connection status, details of the access point if connected to one,
 *  and the ip related info like address, gateway, dns if the service is online
 * 
 *  JSON format:
 *
 *  luna://com.palm.wifi/getstatus {}
 *  luna://com.palm.wifi/getstatus {"subscribe":true}
 *
 *  @param sh
 *  @param message
 *  @param context
 */

bool handle_get_status_command(LSHandle* sh, LSMessage *message, void* context)
{
	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);

	if(!connman_status_check(sh, message))
		return true;

	if(!wifi_technology_status_check(sh, message))
		return true;

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));    	
	jobject_put(reply, J_CSTR_TO_JVAL("wakeOnWlan"), jstring_create("disabled"));    	
	jobject_put(reply, J_CSTR_TO_JVAL("status"), jstring_create(is_wifi_powered() ? "serviceEnabled" : "serviceDisabled"));    	

	connman_manager_update_services(manager);
	/* Get the service which is connecting or already in connected state */
	connman_service_t *connected_service = connman_manager_get_connected_service(manager);
	if(connected_service != NULL)
	{
		add_connected_network_status(&reply, connected_service);
	}

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(!response_schema) {
		LSMessageReplyErrorUnknown(sh,message);
		return;
	}
	
	if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror)) {
        	LSErrorPrint(&lserror, stderr);
        	LSErrorFree(&lserror);
    	}

    	j_release(&reply);
	jschema_release(&response_schema);
    	return true;
}

/**
 * Handler for "getprofile" command.
 *
 * JSON format:
 * luna://com.palm.wifi/getprofile {"profileId":888}
 */
bool handle_get_profile_command(LSHandle *sh, LSMessage *message, void* context)
{
	return true;
}

/**
 * Handler for "getinfo" command.
 *
 * JSON format:
 * luna://com.palm.wifi/getinfo {}
 */
bool handle_get_info_command(LSHandle *sh, LSMessage *message, void* context)
{
	return true;
}

/**
 * Handler for "deleteprofile" command.
 *
 * JSON format:
 * luna://com.palm.wifi/deleteprofile {"profileId":888}
 */

bool handle_delete_profile_command(LSHandle *sh, LSMessage *message, void* context)
{
	return true;
}

/** 
 *  @brief Initialize com.palm.wifi service and all of its methods
 *  Also initialize a manager instance
 */

int initialize_wifi_ls2_calls( GMainLoop *mainloop ) 
{
	LSError lserror;
	LSErrorInit (&lserror);
	pLsHandle       = NULL;
	pLsPublicHandle = NULL;

	if (LSRegisterPubPriv(WIFI_LUNA_SERVICE_NAME, &pLsHandle, false, &lserror) == false)
	{
		g_error("LSRegister() private returned error");
		goto Exit;
	}

	if (LSRegisterPubPriv(WIFI_LUNA_SERVICE_NAME, &pLsPublicHandle, true, &lserror) == false)
	{
		g_error("LSRegister() public returned error");
		goto Exit;
	}

	if (LSRegisterCategory(pLsHandle, NULL, wifi_methods, NULL, NULL, &lserror) == false)
	{
		g_error("LSRegisterCategory() returned error");
		goto Exit;
	}

	if (LSGmainAttach(pLsHandle, mainloop, &lserror) == false)
	{
		g_error("LSGmainAttach() private returned error");
		goto Exit;
	}

	if (LSGmainAttach(pLsPublicHandle, mainloop, &lserror) == false)
	{
		g_error("LSGmainAttach() public returned error");
		goto Exit;
	}

	g_type_init();

	/* We just need one manager instance that stays throughout the lifetime 	   
           of this daemon. Only its technologies and services lists are updated
	   whenever the corresponding signals are received */
	manager = connman_manager_new();
	if(manager == NULL)
	{
		goto Exit;
	}       

	return 0;

Exit:
        if (LSErrorIsSet(&lserror))
        {
       		LSErrorPrint(&lserror, stderr);
	        LSErrorFree(&lserror);
        }

        if (pLsHandle)
        {
                        LSErrorInit (&lserror);
        	    if(LSUnregister(pLsHandle, &lserror) == false)
                        {
                	        LSErrorPrint(&lserror, stderr);
                        	LSErrorFree(&lserror);
                        }
        }

        if (pLsPublicHandle)
        {
                        LSErrorInit (&lserror);
	            if(LSUnregister(pLsPublicHandle, &lserror) == false)
                        {
        	                LSErrorPrint(&lserror, stderr);
                	        LSErrorFree(&lserror);
                        }
        }
	return -1;
}
