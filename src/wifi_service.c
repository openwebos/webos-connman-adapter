/* @@@LICENSE
*
*      Copyright (c) 2012 Hewlett-Packard Development Company, L.P.
*      Copyright (c) 2012 Simon Busch <morphis@gravedo.de>
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
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "wifi_service.h"
#include "wifi_profile.h"
#include "wifi_setting.h"
#include "connman_manager.h"
#include "connman_agent.h"
#include "lunaservice_utils.h"
#include "common.h"
#include "connectionmanager_service.h"

typedef struct connection_settings {
	char *passkey;
	char *ssid;
} connection_settings_t;

static LSHandle *pLsHandle, *pLsPublicHandle;

connman_manager_t *manager = NULL;
static connman_agent_t *agent = NULL;

/* Constant for mapping access point signal strength to signal levels (1 to 3) */
#define MAX_SIGNAL_BARS         3

static connection_settings_t* connection_settings_new(void)
{
	connection_settings_t *settings = NULL;

	settings = g_new0(connection_settings_t, 1);

	return settings;
}

static void connection_settings_free(connection_settings_t *settings)
{
	g_free(settings->passkey);
	g_free(settings->ssid);
	g_free(settings);
}

/**
 *  @brief Returns true if wifi technology is powered on
 *  
 */

static gboolean is_wifi_powered(void)
{
	connman_technology_t *technology = connman_manager_find_wifi_technology(manager);
	if(NULL != technology)
		return technology->powered;
	else
		return FALSE;
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
	if(connman_state == CONNMAN_SERVICE_STATE_ONLINE
		|| connman_state == CONNMAN_SERVICE_STATE_READY)
	{
		connman_service_get_ipinfo(connected_service);
		jvalue_ref ip_info = jobject_create();	

		if(connected_service->ipinfo.iface)
			jobject_put(ip_info, J_CSTR_TO_JVAL("interface"), jstring_create(connected_service->ipinfo.iface));
		if(connected_service->ipinfo.ipv4.address)
			jobject_put(ip_info, J_CSTR_TO_JVAL("ip"), jstring_create(connected_service->ipinfo.ipv4.address));
		if(connected_service->ipinfo.ipv4.netmask)
			jobject_put(ip_info, J_CSTR_TO_JVAL("subnet"), jstring_create(connected_service->ipinfo.ipv4.netmask));
		if(connected_service->ipinfo.ipv4.gateway)
			jobject_put(ip_info, J_CSTR_TO_JVAL("gateway"), jstring_create(connected_service->ipinfo.ipv4.gateway));

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
	if(connected_service != NULL && connman_service_type_wifi(connected_service))
	{
		add_connected_network_status(reply, connected_service);
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

static void service_state_changed_callback(gpointer data, const gchar *new_state)
{
	connman_service_t *service = (connman_service_t *)data;
	if(NULL == service)
		return;
	g_message("Service %s state changed to %s",service->name, new_state);
	int service_state = connman_service_get_state(service->state);
	switch(service_state)
	{
		case  CONNMAN_SERVICE_STATE_CONFIGURATION:
		case  CONNMAN_SERVICE_STATE_READY:
		case  CONNMAN_SERVICE_STATE_ONLINE:
			break;
		default:
			return;
	}

	if(NULL == service->name)
		return;

	wifi_profile_t *profile = get_profile_by_ssid(service->name);
	if(NULL != profile)
	{
		/* If profile already exists, move it to top of the list */
		move_profile_to_head(profile);
	}
	else
	{
		/* Else, create a new profile */
		gchar *security = NULL;
		if(NULL != service->security && !g_str_equal(service->security[0], "none"))
			create_new_profile(service->name, service->security, service->hidden);
		else
			create_new_profile(service->name, NULL, service->hidden);
	}

	/* Unset agent callback as we no longer have any valid input for connman available */
	connman_agent_set_request_input_callback(agent, NULL, NULL);
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
			/* Register for 'state changed' signal for this service to update its connection status */
			/* The hidden services, once connected, get added as a new service in "association" state */
			connman_service_register_state_changed_cb(service, service_state_changed_callback);
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

        for (ap = manager->wifi_services; NULL != ap ; ap = ap->next)
	{
                jvalue_ref network = jobject_create();
                connman_service_t *service = (connman_service_t *)(ap->data);
                if(NULL == service->name)
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


static GVariant* agent_request_input_callback(GVariant *fields, gpointer data)
{
	connection_settings_t *settings = data;
	GVariant *response = NULL;
	GVariantBuilder *vabuilder;
	GVariantIter iter;
	gchar *key;
	GVariant *value;
	if (!g_variant_is_container(fields)) {
		connection_settings_free(settings);
		return NULL;
	}

	vabuilder = g_variant_builder_new("a{sv}");

	g_variant_iter_init(&iter, fields);
	while (g_variant_iter_next(&iter, "{sv}", &key, &value)) {
		if (!strncmp(key, "Name", 10)) {
			g_variant_builder_add(vabuilder, "{sv}", "Name",
				g_variant_new("s", settings->ssid));
		}
		else if (!strncmp(key, "Passphrase", 10)) {
			/* FIXME we're ignoring the other fields here as we're only connecting to
			 * psk secured networks at the moment */
			g_variant_builder_add(vabuilder, "{sv}", "Passphrase",
				g_variant_new("s", settings->passkey));
		}
	}

	response = g_variant_builder_end(vabuilder);
	g_variant_builder_unref(vabuilder);

	connection_settings_free(settings);

	return response;
}

static void service_connect_callback(gboolean success, gpointer user_data)
{
	luna_service_request_t *service_req = user_data;
	if (success) {
		LSMessageReplySuccess(service_req->handle, service_req->message);
	}
	else {
		LSMessageReplyCustomError(service_req->handle, service_req->message, "Failed to connect");
	}

	LSMessageUnref(service_req->message);
	g_free(service_req);
	connman_agent_set_request_input_callback(agent, NULL, NULL);
}

/**
 *  @brief Connect to a access point with the given ssid
 *
 *  @param ssid 
 */

static void connect_wifi_with_ssid(const char *ssid, jvalue_ref req_object, luna_service_request_t *service_req)
{
	jvalue_ref security_obj = NULL;
	jvalue_ref simple_security_obj = NULL;
	jvalue_ref enterprise_security_obj = NULL;
	jvalue_ref passkey_obj = NULL;
	jvalue_ref hidden_obj = NULL;
	raw_buffer passkey_buf;
	GSList *ap;
	gboolean found_service = FALSE, hidden = FALSE, psk_security = FALSE;
	connection_settings_t *settings = NULL;
	connman_service_t *service = NULL;

	if (NULL == ssid)
		return false;

	if (jobject_get_exists(req_object, J_CSTR_TO_BUF("wasCreatedWithJoinOther"), &hidden_obj))
	{
		jboolean_get(hidden_obj, &hidden);
	}

	/* Look up for the service with the given ssid */
        for (ap = manager->wifi_services; NULL != ap ; ap = ap->next)
        {
                service = (connman_service_t *)(ap->data);
		if(NULL == service->name)
		{
			if(hidden)
			{
				if((service->security != NULL) && g_strv_length(service->security))
				{
					gsize i;
					for (i = 0; i < g_strv_length(service->security); i++)
					{
						if(g_str_equal(service->security[i],"psk"))
							psk_security = TRUE;
					}
				}
				if(psk_security)
					found_service = TRUE;
			}
		}
		if(found_service || ((NULL != service->name) && g_str_equal(service->name, ssid)))
		{
			if(NULL == service->name)
				g_message("Connecting to hidden service");
			else
				g_message("Connecting to ssid %s",service->name);

			found_service = TRUE;
			/* Register for 'state changed' signal for this service to update its connection status */
			connman_service_register_state_changed_cb(service, service_state_changed_callback);

			connman_service_t *connected_service = connman_manager_get_connected_service(manager);
			if(connected_service != NULL)
			{
				if(connman_service_type_ethernet(connected_service))
				{
					LSMessageReplyCustomError(service_req->handle, service_req->message, "Connected to wired network");
					goto cleanup;
				}
				else if (connected_service != service) {
					connman_service_disconnect(connected_service);
				}
				else {
					/* Already connected so connection was successful */
					LSMessageReplySuccess(service_req->handle, service_req->message);
					g_message("Already connected with network");
					goto cleanup;
				}
			}
			break;
		}
	}

	if (!found_service) {
		LSMessageReplyCustomError(service_req->handle, service_req->message, "Network not found");
		goto cleanup;
	}

	if (jobject_get_exists(req_object, J_CSTR_TO_BUF("security"), &security_obj))
	{
		settings = connection_settings_new();
		settings->ssid = strdup(ssid);

		/* parse security parameters and set connection settings accordingly */
		if (jobject_get_exists(security_obj, J_CSTR_TO_BUF("simpleSecurity"), &simple_security_obj) &&
			jobject_get_exists(simple_security_obj, J_CSTR_TO_BUF("passKey"), &passkey_obj))
		{
			passkey_buf = jstring_get(passkey_obj);

			settings->passkey = strdup(passkey_buf.m_str);
		}
		else if (jobject_get_exists(security_obj, J_CSTR_TO_BUF("enterpriseSecurity"), &enterprise_security_obj))
		{
			LSMessageReplyCustomError(service_req->handle, service_req->message, "Not implemented");
			goto cleanup;
		}
		else
		{
			LSMessageReplyErrorInvalidParams(service_req->handle, service_req->message);
			goto cleanup;
		}

		g_message("Setup for connecting with secured network");
		connman_agent_set_request_input_callback(agent, agent_request_input_callback, settings);
	}

	if (!connman_service_connect(service, service_connect_callback, service_req))
	{
		LSMessageReplyErrorUnknown(service_req->handle, service_req->message);
		goto cleanup;
	}

	return;
cleanup:
	if (settings != NULL)
		connection_settings_free(settings);

	g_free(service_req);
	LSMessageUnref(service_req->message);
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
		connectionmanager_send_status();

		jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
		if(response_schema)
		{
			const char *payload = jvalue_tostring(reply, response_schema);
			LSError lserror;
			LSErrorInit(&lserror);
			if (!LSSubscriptionPost(pLsHandle, "/", "getstatus", payload, &lserror))
			{
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
	if(response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);
		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionPost(pLsHandle, "/", "findnetworks", payload, &lserror))
		{
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
		if(response_schema)
		{
			const char *payload = jvalue_tostring(reply, response_schema);
//			g_message("Sending \n%s\n to subscribers",payload);
			LSError lserror;

			if (!LSSubscriptionPost(pLsHandle, "/", "getstatus", payload, &lserror))
			{
				LSErrorPrint(&lserror, stderr);
				LSErrorFree(&lserror);
			}
			jschema_release(&response_schema);
		}
		j_release(&reply);
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
	if(!connman_status_check(manager, sh, message))
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

	if (jis_null(parsedObj))
	{
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
 *  @brief Handler for "connect" command.
 *  Connect to a wifi access point with its ssid or its profile Id 
 *  
 *  JSON format:
 *  luna://com.palm.wifi/connect '{"ssid":"<Name of the access point>",
 *                                 "security": { "securityType": "",
 *                                     "simpleSecurity": { "passKey": "<passphrase for the network>" },
 *                                     "enterpriseSecurity": { ... }
 *                                 }
 *                                }'
 *  luna://com.palm.wifi/connect '{"profileId":<Profile ID>}'`
 * 
 *  @param sh
 *  @param message
 *  @param context
 *
 */

static bool handle_connect_command(LSHandle *sh, LSMessage *message, void* context)
{
	luna_service_request_t *service_req;

	if(!connman_status_check(manager, sh, message))
		return true;

	if(!wifi_technology_status_check(sh, message))
		return true;

        if(!is_wifi_powered())
	{
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

        if (jis_null(parsedObj))
	{
                LSMessageReplyErrorBadJSON(sh, message);
                goto cleanup;
        }

        jvalue_ref ssidObj = {0};
        jvalue_ref profileIdObj = {0};
	char *ssid;

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer ssid_buf = jstring_get(ssidObj);
		ssid = g_strdup(ssid_buf.m_str);
	}
	else if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileId"), &profileIdObj))
	{
		if(!jis_number(profileIdObj))
		{
			LSMessageReplyErrorInvalidParams(sh, message);
			goto cleanup;
		}
		int profile_id = 0;
		jnumber_get_i32(profileIdObj, &profile_id);
		wifi_profile_t *profile = get_profile_by_id(profile_id);
		if(NULL == profile)
		{
			LSMessageReplyCustomError(sh, message, "Profile not found");
			goto cleanup;
		}
		ssid = g_strdup(profile->ssid);
	}

	service_req = luna_service_request_new(sh, message);
	LSMessageRef(message);

	connect_wifi_with_ssid(ssid, parsedObj, service_req);

	g_free(ssid);
cleanup:
	j_release(&parsedObj);
	return true;
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

	if(!connman_status_check(manager, sh, message))
		goto cleanup;

	if(!wifi_technology_status_check(sh, message))
		goto cleanup;

	if(!is_wifi_powered())
	{
		LSMessageReplyCustomError(sh,message,"WiFi switched off");
		goto cleanup;
	}

	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);
	if(NULL == wifi_tech)
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
		if(!response_schema)
		{
			LSMessageReplyErrorUnknown(sh,message);
			goto cleanup;
		}
		if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
		jschema_release(&response_schema);
	}
	else
		LSMessageReplySuccess(sh, message);

cleanup:
	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
	j_release(&reply);
	return true;
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

	if (LSMessageIsSubscription(message))
	{
		if (!LSSubscriptionProcess(sh, message, &subscribed, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
		jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));
	}

	if(!connman_status_check(manager, sh, message))
		goto cleanup;

	if(!wifi_technology_status_check(sh, message))
		goto cleanup;

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	send_connection_status(&reply);

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(!response_schema)
	{
		LSMessageReplyErrorUnknown(sh,message);
		goto cleanup;
	}
	
	if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror))
	{
        	LSErrorPrint(&lserror, stderr);
        	LSErrorFree(&lserror);
    	}

	jschema_release(&response_schema);

cleanup:
	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
	j_release(&reply);
	return true;
}

static void add_wifi_profile(jvalue_ref *profile_j, wifi_profile_t *profile)
{
	jvalue_ref profile_details_j = jobject_create();
	jobject_put(profile_details_j, J_CSTR_TO_JVAL("ssid"), jstring_create(profile->ssid));
	jobject_put(profile_details_j, J_CSTR_TO_JVAL("profileId"), jnumber_create_i32(profile->profile_id));
	if(profile->hidden)
	{
		jobject_put(profile_details_j, J_CSTR_TO_JVAL("wasCreatedWithJoinOther"), jboolean_create(profile->hidden));
	}
	if(profile->security != NULL)
	{
		jvalue_ref security = jobject_create();
		jvalue_ref security_list = jarray_create(NULL);
		int i;
		for (i = 0; i < g_strv_length(profile->security); i++)
		{
			jarray_append(security_list, jstring_create(profile->security[i]));
		}
		jobject_put(security, J_CSTR_TO_JVAL("securityType"), security_list);
		jobject_put(profile_details_j, J_CSTR_TO_JVAL("security"), security);
	}
	jobject_put(*profile_j, J_CSTR_TO_JVAL("wifiProfile"), profile_details_j);
}

static void add_wifi_profile_list(jvalue_ref *reply)
{
	if(profile_list_is_empty())
		return;

	jvalue_ref profile_list_j = jarray_create(NULL);

	wifi_profile_t *profile = NULL;
	while(NULL != (profile = get_next_profile(profile)))
	{
		jvalue_ref *profile_j = jobject_create();
		add_wifi_profile(&profile_j, profile);
		jarray_append(profile_list_j, profile_j);
	}
	jobject_put(*reply, J_CSTR_TO_JVAL("profileList"), profile_list_j);
}

/**
 * Handler for "getprofilelist" command.
 *
 * JSON format:
 * luna://com.palm.wifi/getprofilelist {}
 */
static bool handle_get_profilelist_command(LSHandle *sh, LSMessage *message, void* context)
{
	if(!connman_status_check(manager, sh, message))
		return true;

	if(!wifi_technology_status_check(sh, message))
		return true;

	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);

	if(profile_list_is_empty())
	{
		LSMessageReplyCustomError(sh, message, "Profile not found");
		goto cleanup;
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	add_wifi_profile_list(&reply);

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(!response_schema)
	{
		LSMessageReplyErrorUnknown(sh,message);
		goto cleanup;
	}

	if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	jschema_release(&response_schema);

cleanup:
	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

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
	if(!connman_status_check(manager, sh, message))
		return true;

	if(!wifi_technology_status_check(sh, message))
		return true;

	jvalue_ref parsedObj = {0};
	jvalue_ref reply = jobject_create();
	int profile_id = 0;
	LSError lserror;
	LSErrorInit(&lserror);

        jschema_ref input_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
        if(!input_schema)
                return false;

        JSchemaInfo schemaInfo;
        jschema_info_init(&schemaInfo, input_schema, NULL, NULL); // no external refs & no error handlers
        parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)), DOMOPT_NOOPT, &schemaInfo);
        jschema_release(&input_schema);

        if (jis_null(parsedObj))
	{
                LSMessageReplyErrorBadJSON(sh, message);
                goto cleanup;
        }

        jvalue_ref profileIdObj = {0};

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileId"), &profileIdObj))
	{
		if(!jis_number(profileIdObj))
		{
			LSMessageReplyErrorInvalidParams(sh, message);
			goto cleanup;
		}
		jnumber_get_i32(profileIdObj, &profile_id);
	}

	wifi_profile_t *profile = get_profile_by_id(profile_id);
	if(NULL == profile)
	{
		LSMessageReplyCustomError(sh, message, "Profile not found");
		goto cleanup;
	}
	else
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
		add_wifi_profile(&reply, profile);
	}

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(!response_schema)
	{
		LSMessageReplyErrorUnknown(sh,message);
		goto cleanup;
	}

	if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
    	}

	jschema_release(&response_schema);

cleanup:
	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&parsedObj);
	j_release(&reply);
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
	if(!connman_status_check(manager, sh, message))
		return true;

	if(!wifi_technology_status_check(sh, message))
		return true;

	jvalue_ref parsedObj = {0};
	jvalue_ref reply = jobject_create();
	int profile_id = 0;
	LSError lserror;
	LSErrorInit(&lserror);

        jschema_ref input_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
        if(!input_schema)
                return false;

        JSchemaInfo schemaInfo;
        jschema_info_init(&schemaInfo, input_schema, NULL, NULL); // no external refs & no error handlers
        parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)), DOMOPT_NOOPT, &schemaInfo);
        jschema_release(&input_schema);

        if (jis_null(parsedObj))
	{
                LSMessageReplyErrorBadJSON(sh, message);
                goto cleanup;
        }

        jvalue_ref profileIdObj = {0};

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileId"), &profileIdObj))
	{
		if(!jis_number(profileIdObj))
		{
			LSMessageReplyErrorInvalidParams(sh, message);
			goto cleanup;
		}
		jnumber_get_i32(profileIdObj, &profile_id);
	}

	wifi_profile_t *profile = get_profile_by_id(profile_id);
	if(NULL == profile)
	{
		LSMessageReplyCustomError(sh, message, "Profile not found");
		goto cleanup;
	}
	else
	{
		delete_profile(profile);
		LSMessageReplySuccess(sh, message);
	}

cleanup:
	j_release(&parsedObj);
	return true;
}


#define MAC_ADDR_LEN	6

// mac_address must be a pointer to a buffer of at least length 18 (12 hex digits + 5 colons + a null)
//
// Return string is "HH:HH:HH:HH:HH:HH\0"

static int get_wifi_mac_address(char *mac_address)
{
	struct ifreq ifr;
	int s;
	int ret = -1;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s == -1)
	{
		return ret;
	}

	strcpy(ifr.ifr_name, CONNMAN_WIFI_INTERFACE_NAME);
	if(ioctl(s, SIOCGIFHWADDR, &ifr) == 0)
	{
		int i;
		for(i = 0; i < MAC_ADDR_LEN; i++)
		{
			sprintf(&mac_address[i*3], "%02X%s", (unsigned char)ifr.ifr_hwaddr.sa_data[i], (i < (MAC_ADDR_LEN - 1)) ? ":" : "");
		}
		ret = 0;
	}
	return ret;
}

/**
 * Handler for "getinfo" command.
 *
 * JSON format:
 * luna://com.palm.wifi/getinfo {}
 */

static bool handle_get_info_command(LSHandle *sh, LSMessage *message, void* context)
{
	if(!connman_status_check(manager, sh, message))
		return true;

	if(!wifi_technology_status_check(sh, message))
		return true;

	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);
	char mac_address[32]={0};

	if(get_wifi_mac_address(mac_address) < 0)
	{
		LSMessageReplyErrorUnknown(sh,message);
		goto cleanup;
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	jvalue_ref wifi_info = jobject_create();

	jobject_put(wifi_info, J_CSTR_TO_JVAL("macAddress"),jstring_create(mac_address));
	jobject_put(wifi_info, J_CSTR_TO_JVAL("regionCode"),jnumber_create_i32(0));
	jobject_put(wifi_info, J_CSTR_TO_JVAL("wakeOnWlan"),jstring_create("disabled"));
	jobject_put(wifi_info, J_CSTR_TO_JVAL("wmm"),jstring_create("disabled"));
	jobject_put(wifi_info, J_CSTR_TO_JVAL("roaming"),jstring_create("disabled"));
	jobject_put(wifi_info, J_CSTR_TO_JVAL("powerSave"),jstring_create("disabled"));

	jobject_put(reply, J_CSTR_TO_JVAL("wifiInfo"), wifi_info);

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(!response_schema)
	{
		LSMessageReplyErrorUnknown(sh,message);
		goto cleanup;
	}

	if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	jschema_release(&response_schema);

cleanup:
	if (LSErrorIsSet(&lserror))
        {
                LSErrorPrint(&lserror, stderr);
                LSErrorFree(&lserror);
        }

	j_release(&reply);
	return true;
}

static void agent_registered_callback(gpointer user_data)
{
	gchar *agent_path;

	agent_path = connman_agent_get_path(agent);
	if (!connman_manager_register_agent(manager, agent_path)) {
		g_message("Could not register our agent instance with connman; functionality will be limited!");
	}
}

/**
 * com.palm.wifi service Luna Method Table
 */

static LSMethod wifi_methods[] = {
    { LUNA_METHOD_GETPROFILELIST,	handle_get_profilelist_command },
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
	gchar *agent_path = NULL;

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
	if(NULL == manager)
	{
		goto Exit;
	}       

	agent = connman_agent_new();
	if (NULL == agent)
		goto Exit;

	connman_agent_set_registered_callback(agent, agent_registered_callback, NULL);

	/* Register for manager's "PropertyChanged" and "ServicesChanged" signals for sending 'getstatus' and 'findnetworks'
	   methods to their subscribers */
	connman_manager_register_property_changed_cb(manager, manager_property_changed_callback);
	connman_manager_register_services_changed_cb(manager, manager_services_changed_callback);

	/* Register for WiFi technology's "PropertyChanged" signal*/
	connman_technology_t *technology = connman_manager_find_wifi_technology(manager);
	if(technology)
	{
		connman_technology_register_property_changed_cb(technology, technology_property_changed_callback);
	}

	init_wifi_profile_list();
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
