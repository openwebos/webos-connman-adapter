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

static void send_connection_status(jvalue_ref *reply);
static bool populate_wifi_networks(jvalue_ref *reply);

static LSHandle *pLsHandle, *pLsPublicHandle;

static connman_manager_t *manager = NULL;

/* Constant for mapping access point signal strength to signal levels ( 1 to 5) */
#define MAX_SIGNAL_BARS         5

/**
 *  @brief Returns true if wifi technology is powered on
 *  
 */

static gboolean is_wifi_powered(void)
{
	connman_technology_t *technology = connman_manager_find_wifi_technology(manager);
	return technology->powered;
}

/**
 *  @brief Sets the wifi technologies powered state
 *  
 *  @param state
 */

static gboolean set_wifi_state(bool state)
{
	return connman_technology_set_powered(connman_manager_find_wifi_technology(manager),state);
}

/**
 *  @brief Check if the wifi technology is available
 *   Send an error luna message if its not available
 *
 *  @param sh
 *  @param message
 */

static gboolean wifi_technology_status_check(LSHandle *sh, LSMessage *message)
{
	if(NULL == connman_manager_find_wifi_technology(manager))
	{
		LSMessageReplyCustomError(sh, message, "WiFi technology unavailable");
		return false;
	}
	return true;
}

/**
 *  @brief Check if the connman manager is not in offline mode
 *   Send an error luna message if it is in offline mode
 *
 *  @param sh
 *  @param message
 */


static gboolean connman_status_check(LSHandle *sh, LSMessage *message)
{
	if(!connman_manager_is_manager_available(manager))
	{
		LSMessageReplyCustomError(sh, message, "Connman service unavailable");
		return false;
	}
	return true;
}

/**
 *  @brief Callback function registered with connman manager whenever any of its properties change
 *
 *
 *  @param data
 *  @param property
 *  @param value
 */

static void manager_property_changed_callback(gpointer data, const gchar *property, GVariant *value)
{
	/* Send getstatus method to all is subscribers whenever manager's state changes */
	if(g_str_equal(property,"State"))
	{
		jvalue_ref reply = jobject_create();
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

		send_connection_status(&reply);

		jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
		if(response_schema) {
			const char *payload = jvalue_tostring(reply, response_schema);
			g_message("Sending \n%s\n to subscribers",payload);
			LSError lserror;
			LSErrorInit(&lserror);
			if (!LSSubscriptionPost(pLsHandle, "/", "getstatus", payload, &lserror)) {
				LSErrorPrint(&lserror, stderr);
				LSErrorFree(&lserror);
			}
			jschema_release(&response_schema);
		}
		j_release(&reply);
	}
}

/**
 *  @brief Callback function registered with connman manager whenever any of its services change
 *  This would happen whenever any existing service is changed/deleted, or a new service is added
 *
 *  @param data
 */

static void manager_services_changed_callback(gpointer data)
{
	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	/* Send the latest WiFi network list to subscribers of 'findnetworks' method */
	populate_wifi_networks(&reply);

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(response_schema) {
		const char *payload = jvalue_tostring(reply, response_schema);
			g_message("Sending \n%s\n to subscribers",payload);
		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionPost(pLsHandle, "/", "findnetworks", payload, &lserror)) {
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
		jschema_release(&response_schema);
	}
	j_release(&reply);

}

/**
 *  @brief Callback function registered with connman technology whenever any of its properties change
 *
 *
 *  @param data
 *  @param property
 *  @param value
 */

static void technology_property_changed_callback(gpointer data, const gchar *property, GVariant *value)
{
	connman_technology_t *technology = (connman_technology_t *)data;

	if(NULL == technology)
		return;

	if(connman_manager_find_wifi_technology(manager) != technology)
	{
		g_message("Ignoring signals for non-wifi technologies");
		return;
	}
	/* Need to send getstatus method to all its subscribers whenever the "powered" state
	   of WiFi technology changes */

	if(g_str_equal(property,"Powered"))
	{
		jvalue_ref reply = jobject_create();
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

		send_connection_status(&reply);
		jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
		if(response_schema) {
			const char *payload = jvalue_tostring(reply, response_schema);
			g_message("Sending \n%s\n to subscribers",payload);
			LSError lserror;

			if (!LSSubscriptionPost(pLsHandle, "/", "getstatus", payload, &lserror)) {
				LSErrorPrint(&lserror, stderr);
				LSErrorFree(&lserror);
			}
			jschema_release(&response_schema);
		}
		j_release(&reply);
	}
}

/**
 *  @brief Callback function registered with connman service whenever any of its properties change
 *
 *
 *  @param data
 *  @param property
 *  @param value
 */

static void service_property_changed_callback(gpointer data, const gchar *property, GVariant *value)
{
	connman_service_t *service = (connman_service_t *)data;
	if(NULL == service)
		return;

	if(g_str_equal(property,"State"))
	{
		g_free(service->state);
		/* Update service->state so that 'getstatus' method sends the correct values */
		service->state = g_variant_dup_string(g_variant_get_variant(value), NULL);
		g_message("Service %s state changed to %s",service->name, service->state);
	}
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

static bool handle_set_state_command(LSHandle *sh, LSMessage *message, void* context)
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

static bool connect_wifi_with_ssid(const char *ssid)
{
	if(NULL == ssid)
		return false;

 	GSList *ap;

	/* Look up for the service with the given ssid */
        for (ap = manager->services; ap; ap = ap->next)
        {
                connman_service_t *service = (connman_service_t *)(ap->data);
		if(g_str_equal(service->name, ssid)) 
		{               
			g_message("ssid %s found, now connecting",service->name);
			/* Register for 'PropertyChanged' signal for this service to update its connection status */
			connman_service_register_property_changed_cb(service, (connman_property_changed_cb)service_property_changed_callback);
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

static bool handle_connect_command(LSHandle *sh, LSMessage *message, void* context)
{
	if(!connman_status_check(sh, message))
		return true;

	if(!wifi_technology_status_check(sh, message))
		return true;

        if(!is_wifi_powered()) {
                LSMessageReplyCustomError(sh,message,"WiFi switched off");
		return true;
	}

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
 
static void add_service(connman_service_t *service, jvalue_ref *network)
{
	if(NULL == service || NULL == network)
		return;

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
 *  @param reply
 *
 */

static bool populate_wifi_networks(jvalue_ref *reply)
{
	if(NULL == reply)
		return;

        bool networks_found = false;

        jvalue_ref network_list = jarray_create(NULL);

        GSList *ap;

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
                jobject_put(*reply, J_CSTR_TO_JVAL("foundNetworks"), network_list);
        }
        return networks_found;
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

static bool handle_scan_command(LSHandle *sh, LSMessage *message, void* context)
{
	jvalue_ref reply = jobject_create();
	if(!connman_status_check(sh, message))
		goto cleanup;

	if(!wifi_technology_status_check(sh, message))
		goto cleanup;

	if(!is_wifi_powered())
	{
		LSMessageReplyCustomError(sh,message,"WiFi switched off");
		goto cleanup;
	}

	bool subscribed = false;
	LSError lserror;
	LSErrorInit(&lserror);

	if (LSMessageIsSubscription(message))
	{
		if (!LSSubscriptionProcess(sh, message, &subscribed, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
		jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));
	}

	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);
        if(wifi_tech == NULL)
        {
                LSMessageReplySuccess(sh, message);
                goto cleanup;
        }

	/* Scan the network for all available access points by making a connman call*/
        connman_technology_scan_network(wifi_tech);

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	/* Fill in details of all the found wifi networks */
	if(populate_wifi_networks(&reply))
	{
		jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
		if(!response_schema) {
			LSMessageReplyErrorUnknown(sh,message);
			goto cleanup;
		}
		if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror)) {
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
		jschema_release(&response_schema);
	}
	else
		LSMessageReplySuccess(sh, message);

cleanup:
	j_release(&reply);
	return true;
}

 /**
  *  @brief Add details about the connected service
  * 
  *  @param reply
  *  @param connected_service
  *
  */

static void add_connected_network_status(jvalue_ref *reply, connman_service_t *connected_service)
{
	if(NULL == reply || NULL == connected_service)
		return;

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
 * @brief Fill in all status information to be sent with 'getstatus' method
 */

static void send_connection_status(jvalue_ref *reply)
{
	if(NULL == reply)
		return;

	jobject_put(*reply, J_CSTR_TO_JVAL("wakeOnWlan"), jstring_create("disabled"));
	jobject_put(*reply, J_CSTR_TO_JVAL("status"), jstring_create(is_wifi_powered() ? "serviceEnabled" : "serviceDisabled"));

	/* Get the service which is connecting or already in connected state */
	connman_service_t *connected_service = connman_manager_get_connected_service(manager);
	if(connected_service != NULL)
	{
		add_connected_network_status(reply, connected_service);
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

static bool handle_get_status_command(LSHandle* sh, LSMessage *message, void* context)
{
	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);
	bool subscribed = false;

	if(!connman_status_check(sh, message))
		return true;

	if(!wifi_technology_status_check(sh, message))
		return true;

	if (LSMessageIsSubscription(message))
	{
		if (!LSSubscriptionProcess(sh, message, &subscribed, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
		jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	send_connection_status(&reply);

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(!response_schema) {
		LSMessageReplyErrorUnknown(sh,message);
		goto cleanup;
	}
	
	if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror)) {
        	LSErrorPrint(&lserror, stderr);
        	LSErrorFree(&lserror);
    	}

	jschema_release(&response_schema);

cleanup:
	j_release(&reply);
    	return true;
}

/**
 * Handler for "getprofile" command.
 *
 * JSON format:
 * luna://com.palm.wifi/getprofile {"profileId":888}
 */
static bool handle_get_profile_command(LSHandle *sh, LSMessage *message, void* context)
{
	return true;
}

/**
 * Handler for "getinfo" command.
 *
 * JSON format:
 * luna://com.palm.wifi/getinfo {}
 */
static bool handle_get_info_command(LSHandle *sh, LSMessage *message, void* context)
{
	return true;
}

/**
 * Handler for "deleteprofile" command.
 *
 * JSON format:
 * luna://com.palm.wifi/deleteprofile {"profileId":888}
 */

static bool handle_delete_profile_command(LSHandle *sh, LSMessage *message, void* context)
{
	return true;
}

/**
 * com.palm.wifi service Luna Method Table
 */

static LSMethod wifi_methods[] = {
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

	if(NULL == mainloop)
		goto Exit;

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

	/* Register for manager's "PropertyChanged" and "ServicesChanged" signals for sending 'getstatus' and 'findnetworks'
	   methods to their subscribers */
	connman_manager_register_property_changed_cb(manager, (connman_property_changed_cb)manager_property_changed_callback);
	connman_manager_register_services_changed_cb(manager, (connman_services_changed_cb)manager_services_changed_callback);

	/* Register for WiFi technology's "PropertyChanged" signal*/
	connman_technology_t *technology = connman_manager_find_wifi_technology(manager);
	if(technology)
	{
		connman_technology_register_property_changed_cb(technology, (connman_property_changed_cb)technology_property_changed_callback);
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
