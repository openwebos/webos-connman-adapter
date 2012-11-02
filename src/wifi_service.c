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

#include <glib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <lunaservice_utils.h>

#include "wifi_service.h"
#include "connman_manager.h"


bool handle_get_profile_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_get_info_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_connect_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_set_state_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_scan_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_delete_profile_command(LSHandle *sh, LSMessage *message, void* context);
bool handle_get_status_command(LSHandle* sh, LSMessage *message, void* context);

/**
 * WiFi Service Luna Method Table
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

#define MAX_SIGNAL_BARS         5

gboolean is_wifi_powered(void)
{
	connman_technology_t *technology = connman_manager_find_wifi_technology(manager);
	return technology->powered;
}


gboolean set_wifi_state(bool state)
{
	return connman_technology_set_powered(connman_manager_find_wifi_technology(manager),state);
}

gboolean wifi_technology_status_check(LSHandle *sh, LSMessage *message)
{
	if(!connman_manager_find_wifi_technology(manager))
	{
		LSMessageReplyCustomError(sh, message, "WiFi technology unavailable");
		return false;
	}
	return true;
}

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
 * Handler for "setstate" command.
 *
 * JSON format:
 * luna://com.palm.wifi/setstate {"state":"enabled"}
 */
bool handle_set_state_command(LSHandle *sh, LSMessage *message, void* context)
{
	struct json_object *object = json_tokener_parse(
                                    LSMessageGetPayload(message));
	if (is_error(object))
	{
        	LSMessageReplyErrorBadJSON(sh, message);
        	goto cleanup;
    	}
	
	if(!connman_status_check(sh, message))
		goto cleanup;

	if(!wifi_technology_status_check(sh, message))
		goto cleanup;

	char *state = json_object_get_string(
               json_object_object_get(object, "state"));

	if(strncmp(state,"enabled",sizeof(state)) && strncmp(state,"disabled",sizeof(state))) 
	{
        	LSMessageReplyErrorBadJSON(sh, message);
        	goto cleanup;
	}		
	
	bool enable_wifi = !strncmp(state,"enabled",sizeof(state))?true:false;

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

	if (!is_error(object)) json_object_put(object);
	return true;

}

bool connect_wifi_with_ssid(const char *ssid)
{
 	GSList *ap;

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
				g_error("Error in connecting");
				return false;
			}		
		}
        }
	return false;
}

/**
 * Handler for "connectprofile" command.
 *
 * JSON format:
 * luna://com.palm.wifi/connectprofile {"profileId":888}
 */
bool handle_connect_command(LSHandle *sh, LSMessage *message, void* context)
{
	struct json_object *object = json_tokener_parse(LSMessageGetPayload(message));
        if (is_error(object))
        {
                LSMessageReplyErrorBadJSON(sh, message);
                goto cleanup;
        }

	if(!connman_status_check(sh, message))
		goto cleanup;

	if(!wifi_technology_status_check(sh, message))
		goto cleanup;

        if(!is_wifi_powered()) {
                LSMessageReplyCustomError(sh,message,"WiFi switched off");
		goto cleanup;
	}

	connman_manager_update_services(manager);

        char *ssid = json_object_get_string(
               json_object_object_get(object, "ssid"));

	if(ssid)
	{
		if(connect_wifi_with_ssid(ssid))
        		LSMessageReplySuccess(sh, message);
		else
        		LSMessageReplyErrorUnknown(sh, message);

	}
	
cleanup:
	if (!is_error(object)) json_object_put(object);
	return true;
}

void add_service(connman_service_t *service, struct json_object *network_json)
{
	struct json_object *security_list;

	if(service->name != NULL)	
		json_object_object_add(network_json,"ssid",json_object_new_string(service->name));

	if((service->security != NULL) && g_strv_length(service->security))
	{
		gsize i;
		security_list = json_object_new_array();
		for (i = 0; i < g_strv_length(service->security); i++)
		{
			json_object_array_add(security_list, json_object_new_string(service->security[i]));
		}
		json_object_object_add(network_json, "availableSecurityTypes", security_list);
	
	}

	int signalbars = (service->strength * MAX_SIGNAL_BARS) / 100;

	json_object_object_add(network_json, "signalBars",json_object_new_int(signalbars));
	json_object_object_add(network_json, "signalLevel", json_object_new_int(service->strength));

	if(service->state != NULL) 
	{
		if(connman_service_get_state(service->state) != CONNMAN_SERVICE_STATE_IDLE)
		{
			json_object_object_add(network_json, "connectState",
        	       	json_object_new_string(get_webos_state(connman_service_get_state(service->state))));		
		}
	}
}

void populate_wifi_networks(LSHandle *sh, LSMessage *message)
{
	struct json_object *reply;
	struct json_object *network_list_json, *network_json;
	bool networks_found = false;  
	LSError lserror;
	
	reply = json_object_new_object();	
	network_list_json = json_object_new_array();
	GSList *ap;

	connman_manager_update_services(manager);
	
	for (ap = manager->services; ap; ap = ap->next)
	{
		connman_service_t *service = (connman_service_t *)(ap->data);
		if(!is_service_type_wifi(service) || (service->name == NULL))
			continue;
 		network_json = json_object_new_object();
		add_service(service, network_json);
		
		struct json_object *network_info_json = json_object_new_object();
		json_object_object_add(network_info_json,"networkInfo",network_json);
		json_object_array_add(network_list_json, network_info_json);
		networks_found = true;
        }

	if(networks_found)
	{
		json_object_object_add(reply, "returnValue", json_object_new_boolean(true));
		json_object_object_add(reply, "foundNetworks", network_list_json);

	    	if (!LSMessageReply(sh, message, json_object_to_json_string(reply), &lserror)) {
		        LSErrorPrint(&lserror, stderr);
		        LSErrorFree(&lserror);
    		}
	}
	else
        	LSMessageReplySuccess(sh, message);
cleanup:
	json_object_put(reply);
}

/**
 * Handler for "findnetworks" command.
 *
 * JSON format:
 * luna://com.palm.wifi/findnetworks {}
 * luna://com.palm.wifi/findnetworks {"subscribe":true}
 */
bool handle_scan_command(LSHandle *sh, LSMessage *message, void* context)
{
	GError *error = NULL;

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

        connman_technology_scan_network(wifi_tech);

	populate_wifi_networks(sh, message);	
cleanup:
	return true;
}

void add_connected_network_status(struct json_object *reply, connman_service_t *connected_service)
{
	struct json_object *networkinfo_json, *ipinfo_json;
	int connman_state;

	json_object_object_add(reply, "status", json_object_new_string("connectionStateChanged"));

    	networkinfo_json = json_object_new_object();	

	if(connected_service->name != NULL)
		json_object_object_add(networkinfo_json, "ssid",json_object_new_string(connected_service->name));
	if(connected_service->state != NULL)
	{
		connman_state = connman_service_get_state(connected_service->state);
        	json_object_object_add(networkinfo_json, "connectState",
        		json_object_new_string(get_webos_state(connman_state)));   
	}

	json_object_object_add(networkinfo_json, "signalBars",
	json_object_new_int((connected_service->strength * MAX_SIGNAL_BARS) / 100));
	json_object_object_add(networkinfo_json, "signalLevel", json_object_new_int(connected_service->strength));

	json_object_object_add(reply, "networkInfo", networkinfo_json);

	if(connman_state == CONNMAN_SERVICE_STATE_ONLINE)
	{
		connman_service_get_ipinfo(connected_service);
		
		ipinfo_json = json_object_new_object();

        	json_object_object_add(ipinfo_json, "interface", json_object_new_string(connected_service->ipinfo.iface));
        	json_object_object_add(ipinfo_json, "ip", json_object_new_string(connected_service->ipinfo.address));
        	json_object_object_add(ipinfo_json, "subnet", json_object_new_string(connected_service->ipinfo.netmask));
        	json_object_object_add(ipinfo_json, "gateway", json_object_new_string(connected_service->ipinfo.gateway));

		gsize i;
		gchar dns_str[16];
		for (i = 0; i < g_strv_length(connected_service->ipinfo.dns); i++)
		{
			sprintf(dns_str,"dns%d",i+1);
			json_object_object_add(ipinfo_json, dns_str, json_object_new_string(connected_service->ipinfo.dns[i]));
		}

        	json_object_object_add(reply, "ipInfo", ipinfo_json);
        }
}


/**
 * Handler for "getstatus" command.
 *
 * JSON format:
 *
 * luna://com.palm.wifi/getstatus {}
 * luna://com.palm.wifi/getstatus {"subscribe":true}
 */
bool handle_get_status_command(LSHandle* sh, LSMessage *message, void* context)
{
	struct json_object *reply;
	LSError lserror;
	LSErrorInit(&lserror);

	if(!connman_status_check(sh, message))
		goto done;

	if(!wifi_technology_status_check(sh, message))
		goto done;

	reply = json_object_new_object();
    	json_object_object_add(reply, "returnValue", json_object_new_boolean(true));
	json_object_object_add(reply, "wakeOnWlan", json_object_new_string("disabled"));
	json_object_object_add(reply, "status",
        json_object_new_string(is_wifi_powered() ? "serviceEnabled" : "serviceDisabled"));

	connman_manager_update_services(manager);
	connman_service_t *connected_service = connman_manager_get_connected_service(manager);
	if(connected_service != NULL)
	{
		add_connected_network_status(reply, connected_service);
	}

    	if (!LSMessageReply(sh, message, json_object_to_json_string(reply), &lserror)) {
        	LSErrorPrint(&lserror, stderr);
        	LSErrorFree(&lserror);
    	}

    	json_object_put(reply);
done:
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


