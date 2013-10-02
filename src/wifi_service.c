/* @@@LICENSE
*
*      Copyright (c) 2012-2013 LG Electronics, Inc.
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


//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi

@brief Manages connections to Wireless Networks

Each call has a standard return in the case of a failure, as follows:

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | False to inidicate an error
errorCode | Yes | Integer | Error code
errorText | Yes | String | Error description

@{
@}
*/
//->End of API documentation comment block



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
#include "logging.h"

/* Range for converting signal strength to signal bars */
#define MID_SIGNAL_RANGE_LOW	34
#define MID_SIGNAL_RANGE_HIGH	50

typedef struct connection_settings {
	char *passkey;
	char *ssid;
	bool wpsmode;
	char *wpspin;
} connection_settings_t;

/* Schedule a scan every 15 seconds */
#define WIFI_DEFAULT_SCAN_TIMEOUT	15000

static LSHandle *pLsHandle, *pLsPublicHandle;

connman_manager_t *manager = NULL;
static connman_agent_t *agent = NULL;

guint scan_timeout_source = 0;
guint current_scan_interval = 0;

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
	g_free(settings->wpspin);
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
	/* if scan is still scheduled abort it */
	if (scan_timeout_source > 0)
	{
		g_source_remove(scan_timeout_source);
		scan_timeout_source = 0;
	}

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
 * Convert signal strength to signal bars
 *
 * @param[IN] strength Signal strength
 *
 * @return Mapped signal strength in bars
 */

static int signal_strength_to_bars(int strength)
{
	if(strength > 0 && strength < MID_SIGNAL_RANGE_LOW)
		return 1;
	else if(strength >= MID_SIGNAL_RANGE_LOW && strength < MID_SIGNAL_RANGE_HIGH)
		return 2;
	else if(strength >= MID_SIGNAL_RANGE_HIGH)
		return 3;
	return 0;
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

	wifi_profile_t *profile = get_profile_by_ssid(connected_service->name);
	if(NULL != profile)
	{
		jobject_put(network_info, J_CSTR_TO_JVAL("profileId"), jnumber_create_i32(profile->profile_id));
	}

	if(connected_service->state != NULL)
	{
		connman_state = connman_service_get_state(connected_service->state);
		jobject_put(network_info, J_CSTR_TO_JVAL("connectState"), jstring_create(connman_service_get_webos_state(connman_state)));
	}

	jobject_put(network_info, J_CSTR_TO_JVAL("signalBars"), jnumber_create_i32(signal_strength_to_bars(connected_service->strength))); 
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

		if(connected_service->ipinfo.ipv4.method)
			jobject_put(ip_info, J_CSTR_TO_JVAL("method"), jstring_create(connected_service->ipinfo.ipv4.method));

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
	connman_service_t *connected_service = connman_manager_get_connected_service(manager->wifi_services);
	if(connected_service != NULL)
	{
		add_connected_network_status(reply, connected_service);
	}
}

static void send_connection_status_to_subscribers(const gchar *service_state)
{
	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	send_connection_status(&reply);

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);
		WCA_LOG_DEBUG("Sending payload : %s",payload);
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

	/* If the service state is different from manager state, send 'getstatus'
	   method to com.palm.connectionmanager subscribers as well */
	if(NULL != service_state && g_strcmp0(manager->state, service_state))
	{
		connectionmanager_send_status();
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
	WCA_LOG_DEBUG("Service %s state changed to %s",service->name, new_state);

	int service_state = connman_service_get_state(service->state);
	switch(service_state)
	{
		case  CONNMAN_SERVICE_STATE_CONFIGURATION:
			break;
		case  CONNMAN_SERVICE_STATE_READY:
		case  CONNMAN_SERVICE_STATE_ONLINE:
			send_connection_status_to_subscribers(service->state);
			connman_service_set_autoconnect(service, TRUE);
			break;
		case CONNMAN_SERVICE_STATE_IDLE:
			send_connection_status_to_subscribers(service->state);
			return;
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

	gboolean supported = TRUE;

	jobject_put(*network, J_CSTR_TO_JVAL("ssid"), jstring_create(service->name));

	wifi_profile_t *profile = get_profile_by_ssid(service->name);
	if(NULL != profile)
	{
		jobject_put(*network, J_CSTR_TO_JVAL("profileId"), jnumber_create_i32(profile->profile_id));
	}

	if((service->security != NULL) && g_strv_length(service->security))
	{
		gsize i;
		jvalue_ref security_list = jarray_create(NULL);
		for (i = 0; i < g_strv_length(service->security); i++)
		{
			// We do not support enterprise security i.e "ieee8021x" security type
			if(!g_strcmp0(service->security[i],"ieee8021x"))
				supported = FALSE;
			jarray_append(security_list, jstring_create(service->security[i]));
		}
		jobject_put(*network, J_CSTR_TO_JVAL("availableSecurityTypes"),security_list);
	}

	jobject_put(*network, J_CSTR_TO_JVAL("signalBars"),jnumber_create_i32(signal_strength_to_bars(service->strength)));
	jobject_put(*network, J_CSTR_TO_JVAL("signalLevel"),jnumber_create_i32(service->strength));
	jobject_put(*network, J_CSTR_TO_JVAL("supported"),jboolean_create(supported));

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
		return false;

        bool networks_found = false;

        jvalue_ref network_list = jarray_create(NULL);

        GSList *ap;

        /* Go through the manager's services list and fill in details
           for each one of them */

        for (ap = manager->wifi_services; NULL != ap ; ap = ap->next)
	{
                connman_service_t *service = (connman_service_t *)(ap->data);
                if(NULL == service->name)
                        continue;

		jvalue_ref network = jobject_create();
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
	vabuilder = g_variant_builder_new((const GVariantType *)"a{sv}");

	g_variant_iter_init(&iter, fields);
	while (g_variant_iter_next(&iter, "{sv}", &key, &value))
	{
		if (!strncmp(key, "Name", 10))
		{
			if(NULL != settings->ssid)
			{
				g_variant_builder_add(vabuilder, "{sv}", "Name",
					g_variant_new("s", settings->ssid));
			}
		}
		else if (!strncmp(key, "Passphrase", 10))
		{
			/* FIXME we're ignoring the other fields here as we're only connecting to
			 * psk secured networks at the moment */
			if(NULL != settings->passkey)
			{
				g_variant_builder_add(vabuilder, "{sv}", "Passphrase",
					g_variant_new("s", settings->passkey));
			}
		}
		else if (!strncmp(key, "WPS", 10))
		{
			if(settings->wpsmode)
			{
				if(settings->wpspin != NULL)
				{
					g_variant_builder_add(vabuilder, "{sv}", "WPS",
						g_variant_new("s", settings->wpspin));
				}
			}
		}
	}

	response = g_variant_builder_end(vabuilder);
	g_variant_builder_unref(vabuilder);

	connection_settings_free(settings);

	connman_agent_set_request_input_callback(agent, NULL, NULL);
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
	jvalue_ref wps_obj = NULL;
	jvalue_ref wpspin_obj = NULL;

	raw_buffer passkey_buf, wpspin_buf;
	GSList *ap;
	gboolean found_service = FALSE, psk_security = FALSE;
	connection_settings_t *settings = NULL;
	connman_service_t *service = NULL;
	bool hidden = false;

	if (NULL == ssid)
		return;

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
				WCA_LOG_INFO("Connecting to hidden service");
			else
				WCA_LOG_INFO("Connecting to ssid %s",service->name);

			found_service = TRUE;

			connman_service_t *connected_service = connman_manager_get_connected_service(manager->wifi_services);
			if(NULL != connected_service)
			{
				if(connected_service != service) {
					connman_service_disconnect(connected_service);
				}
				else {
					/* Already connected so connection was successful */
					LSMessageReplySuccess(service_req->handle, service_req->message);
					WCA_LOG_DEBUG("Already connected with network");
					goto cleanup;
				}
			}
			/* Register for 'state changed' signal for this service to update its connection status */
			connman_service_register_state_changed_cb(service, service_state_changed_callback);
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
			jstring_free_buffer(passkey_buf);
		}
		else if (jobject_get_exists(security_obj, J_CSTR_TO_BUF("enterpriseSecurity"), &enterprise_security_obj))
		{
			LSMessageReplyCustomError(service_req->handle, service_req->message, "Not implemented");
			goto cleanup;
		}
		else if (jobject_get_exists(security_obj, J_CSTR_TO_BUF("wps"), &wps_obj))
		{
			jboolean_get(wps_obj, &settings->wpsmode);
			if (jobject_get_exists(security_obj, J_CSTR_TO_BUF("wpsPin"), &wpspin_obj))
			{
				wpspin_buf = jstring_get(wpspin_obj);
				settings->wpspin = strdup(wpspin_buf.m_str);
				jstring_free_buffer(wpspin_buf);
			}
			else
			{
				// Setting a default value if no pin is provided
				settings->wpspin = strdup("nopin");
			}
		}
		else
		{
			LSMessageReplyErrorInvalidParams(service_req->handle, service_req->message);
			goto cleanup;
		}

		WCA_LOG_DEBUG("Setup for connecting with secured network");
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
		connectionmanager_send_status();
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

	/* Need to send getstatus method to all its subscribers whenever the "powered" state
	   of WiFi technology changes */
	if(g_str_equal(property,"Powered"))
	{
		send_connection_status_to_subscribers(NULL);
		connectionmanager_send_status();
	}
}

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_setstate setstate

Enable or Disable WIFI support

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
state | Yes | String | "enabled" or "disabled" to control WIFI accordingly

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

@par Returns(Subscription)
None

@}
*/
//->End of API documentation comment block

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
        	return true;
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
			goto invalid_params;
		}
	}
	else
	{
		goto invalid_params;
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
	goto cleanup;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);
cleanup:
	j_release(&parsedObj);
	return true;

}

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_connect connect

@par To Connect to open, hidden or secure networks

Connects to the given ssid , which can be an open network (requiring 
no passphrase i.e no 'security' field in its argument), hidden 
(requiring 'wasCreatedWithJoinOther' field set to true in its argument),
or secure networks (authenticating with provided passphrase).

Note: webos-connman-adapter only supports simple security using psk, 
it doesn't support "enterprise" security.

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | SSID of desired network
wasCreatedWithJoinOther | Yes | String | Set True for a hidden network
security | Only for secure networks | Object | Security information for establishing a connection

@par "security" Object
Name | Required | Type | Description
-----|--------|------|----------
securityType | Yes | String | Connection type, e.g. wpa-personal, wep, or psk
simpleSecurity | Yes | Object | Connection information for a simple connection

@par "simpleSecurity" Object
Name | Required | Type | Description
-----|--------|------|----------
passKey | Yes | String | Passkey for connection to network

@par To connect to wps enabled networks:
Connects to the given ssid with wps setup, for WPS-PBC mode or WPS-PIN mode with
pin to be entered at AP, you just need to set the "wps" field set to true, for
WPS-PIN mode where pin needs to be entered on the device, you need to also enter
the "wpspin" value

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | SSID of desired network
security | Yes | Object | Security information for establishing a connection

@par "security" Object
Name | Required | Type | Description
-----|--------|------|----------
wps | Yes | Boolean | true to enable wps mode
wpspin | No | String | WPS PIN if using WPS-PIN mode

@par To connect to a known profile
Connects to an AP using its profileId which is listed in 'getprofilelist' method.

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
profileId | Yes | String | Name of desired profile

@par Returns(Call) for all forms
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

@par Returns(Subscription)
None

@}
*/
//->End of API documentation comment block

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
                return true;
        }

        jvalue_ref ssidObj = {0};
        jvalue_ref profileIdObj = {0};
	char *ssid;

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer ssid_buf = jstring_get(ssidObj);
		ssid = g_strdup(ssid_buf.m_str);
		jstring_free_buffer(ssid_buf);
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
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	service_req = luna_service_request_new(sh, message);
	LSMessageRef(message);

	connect_wifi_with_ssid(ssid, parsedObj, service_req);

	g_free(ssid);
cleanup:
	j_release(&parsedObj);
	return true;
}

gboolean scan_timeout_cb(gpointer user_data)
{
	LSError error;
	LSHandle *sh = user_data;
	LSSubscriptionIter *iter = NULL;
	unsigned int subscription_count = 0;
	connman_technology_t *wifi_tech = 0;

	LSErrorInit(&error);

	if (!LSSubscriptionAcquire(sh, "/" LUNA_METHOD_FINDNETWORKS, &iter, &error))
	{
		LSErrorPrint(&error, stderr);
		LSErrorFree(&error);

		/* we could not count pending subscriptions so we assume we don't have any users
		 * connected which are waiting for further scan results. */
		scan_timeout_source = 0;
		return FALSE;
	}

	/* count all subscription we have for com.palm.wifi/findnetworks */
	while (LSSubscriptionHasNext(iter))
	{
		LSMessage *message = LSSubscriptionNext(iter);
		LSMessageUnref(message);
		subscription_count++;
	}

	/* if we don't have any subscriptions left we don't have to scan anymore */
	if (subscription_count == 0)
	{
		scan_timeout_source = 0;
		return FALSE;
	}

	wifi_tech = connman_manager_find_wifi_technology(manager);
	connman_technology_scan_network(wifi_tech);

	return TRUE;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_findnetworks findnetworks

List all available wifi access points found in the area.

Callers can subscribe to this method to be notified of any changes. If a
caller subscribes to further results he has to unsubscribe once it doesn't
need fresh results any more. Once more than one client is subscribed a
scan for available wifi networks is scheduled every 30 seconds until no
client is subscribed anymore.

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
subscribe | No | Boolean | true to subcribe to changes
interval | No | Integer | Internval in seconds to schedule a new scan (defaults to 30 seconds)

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
foundNetworks | Yes | Array of Objects | List of networkInfo objects

@par "networkInfo" Object
Each entry in the "foundNetworks" array is of the form "networkInfo":{...}
Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | SSID of discovered AP
availableSecurityTypes | Yes | Array of String | List of supported security mechanisms
signalBars | Yes | Integer | Coarse indication of signal strength
signalLevel | Yes | Integer | Fine indication of signal strength

@par Returns(Subscription)
As for a successful call

@}
*/
//->End of API documentation comment block

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

static bool handle_findnetworks_command(LSHandle *sh, LSMessage *message, void* context)
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
		if(!connman_manager_is_manager_available(manager))
			goto response;
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

	/* only scan if we don't have a scheduled scan pending */
	if (scan_timeout_source > 0)
	{
		connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);
		if(NULL == wifi_tech)
		{
			LSMessageReplySuccess(sh, message);
			goto cleanup;
		}

		if(!connman_technology_scan_network(wifi_tech))
		{
			LSMessageReplyCustomError(sh,message,"Error in scanning network");
			goto cleanup;
		}
	}

	/* If client has subscribed we need to take care that we give him fresh results
	 * regularly by scheduling a scan continously in a specific interval */
	if (subscribed && scan_timeout_source == 0)
	{
		int scan_interval = WIFI_DEFAULT_SCAN_TIMEOUT;

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
				return true;
		}

		jvalue_ref intervalObj = 0;
		if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("interval"), &intervalObj))
		{
			if (!jis_number(intervalObj))
			{
				LSMessageReplyErrorInvalidParams(sh, message);
				goto cleanup;
			}

			jnumber_get_i32(intervalObj, &scan_interval);
		}

		scan_timeout_source = g_timeout_add_full(G_PRIORITY_DEFAULT, scan_interval,
												 scan_timeout_cb, sh, NULL);
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	if(!populate_wifi_networks(&reply))
	{
		LSMessageReplySuccess(sh, message);
		goto cleanup;
	}
response:
	{
		/* Fill in details of all the found wifi networks */
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

cleanup:
	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
	j_release(&reply);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_getstatus getstatus

Gets the current status of wifi connection on the system. 

Callers can subscribe to this method to be notified of any changes
in the wifi connection status.

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
subscribe | No | Boolean | true to subscribe to this method

@par Returns(Call)
All optional fields are absent if WIFI is not connected
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
wakeOnWlan | No | String | provided for backwards compatibility and always set to "disabled"
status | No | String | Set to "connectedStateChanged" for backwards compatibility
networkInfo | No | Object | A single object describing the current connection

@par "networkInfo" Object
Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | SSID of AP
connectState | Yes | String | One of {notAssociated, associating, associated, ipConfigured, ipFailed}
signalBars | Yes | Integer | Coarse indication of signal strength (1..3)
signalLevel | Yes | Integer | Absolute indication of signal strength
ipInfo | Yes | Object | See below

@par "ipInfo" Object
Name | Required | Type | Description
-----|--------|------|----------
interface | Yes | String | interface
ip | Yes | String | IP Address
subnet | Yes | String | Subnet mask value
gateway | Yes | String |IP Address of network gateway
dns | Yes | Array of String | List of DNS server IP addresses

@par Returns(Subscription)
As for a successful call
@}
*/
//->End of API documentation comment block


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
		if(!connman_manager_is_manager_available(manager))
			goto response;
	}

	if(!connman_status_check(manager, sh, message))
		goto cleanup;

	if(!wifi_technology_status_check(sh, message))
		goto cleanup;

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	send_connection_status(&reply);

response:
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
		jvalue_ref profile_j = jobject_create();
		add_wifi_profile(&profile_j, profile);
		jarray_append(profile_list_j, profile_j);
	}
	jobject_put(*reply, J_CSTR_TO_JVAL("profileList"), profile_list_j);
}

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_getprofilelist getprofilelist

Lists all the stored wifi profiles on the system. 

@Note If the wifi AP is an open network with no security, it 
      won't list the "security" field.

@par Parameters
None

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
profileList | yes | Array of Object | Array of wifiProfile objects

@par "wifiProfile" Object
Name | Required | Type | Description
-----|--------|------|----------
ssid | yes | String | SSID associated with the profile
profileId | yes | String | ID string naming the profile (can be used with connect method)
security | no | Object | Contains a "securityType" object, which is an Array of String

@par Returns(Subscription)
None.

@}
*/
//->End of API documentation comment block

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

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_getprofile getprofile

Lists the profile with the given profile ID on the system. 

@Note As in getprofilelist, even here the open networks won't list
      the "security" field.

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
profileId | yes | String | Name of profile required

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
wifiProfile | yes | Object | A "wifiProfile" object as described for the getprofilelist method

@par Returns(Subscription)
None

@}
*/
//->End of API documentation comment block

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
                return true;
        }

        jvalue_ref profileIdObj = {0};
	jvalue_ref reply = jobject_create();
	int profile_id = 0;
	LSError lserror;
	LSErrorInit(&lserror);

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileId"), &profileIdObj))
	{
		if(!jis_number(profileIdObj))
		{
			LSMessageReplyErrorInvalidParams(sh, message);
			goto cleanup;
		}
		jnumber_get_i32(profileIdObj, &profile_id);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
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

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_deleteprofile deleteprofile

Deletes the profile with the given profile ID

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
profileId | Yes | String | Name of profile to be deleted

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

@par Returns(Subscription)
None

@}
*/
//->End of API documentation comment block

/**
 * Handler for "deleteprofile" command.
 * This command should delete the profile as well as disconnect the service matching this profile
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
                return true;
        }

        jvalue_ref profileIdObj = {0};
	int profile_id = 0;
	LSError lserror;
	LSErrorInit(&lserror);

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileId"), &profileIdObj))
	{
		if(!jis_number(profileIdObj))
		{
			LSMessageReplyErrorInvalidParams(sh, message);
			goto cleanup;
		}
		jnumber_get_i32(profileIdObj, &profile_id);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	wifi_profile_t *profile = get_profile_by_id(profile_id);
	if(NULL == profile)
	{
		LSMessageReplyCustomError(sh, message, "Profile not found");
		goto cleanup;
	}
	else
	{
		GSList *ap = NULL;
		/* Look up for any existing service with ssid same as this profile*/
		for (ap = manager->wifi_services; ap; ap = ap->next)
		{
			connman_service_t *service = (connman_service_t *)(ap->data);
			if(!g_strcmp0(service->name, profile->ssid) && NULL != service->state)
			{
				int service_state = connman_service_get_state(service->state);

				switch(service_state)
				{
					case  CONNMAN_SERVICE_STATE_ASSOCIATION:
					case  CONNMAN_SERVICE_STATE_CONFIGURATION:
					case  CONNMAN_SERVICE_STATE_READY:
					case  CONNMAN_SERVICE_STATE_ONLINE:
						/* Disconnect the service */
						connman_service_disconnect(service);
						break;
					default:
						continue;
				}
				/* Deleting profile for this ssid, so set autoconnect property for this 
				   service to FALSE so that connman doesn't autoconnect to this service next time */
				connman_service_set_autoconnect(service, FALSE);
				/* Remove the service from connman */
				connman_service_remove(service);
			}
		}
		delete_profile(profile);
		LSMessageReplySuccess(sh, message);
	}

cleanup:
	j_release(&parsedObj);
	return true;
}

static void agent_registered_callback(gpointer user_data)
{
	gchar *agent_path;

	agent_path = connman_agent_get_path(agent);
	if (!connman_manager_register_agent(manager, agent_path)) {
		WCA_LOG_CRITICAL("Could not register our agent instance with connman; functionality will be limited!");
	}
}


static void connman_service_stopped(GDBusConnection *conn, const gchar *name, const gchar *name_owner, gpointer user_data)
{
	if(agent != NULL) connman_agent_free(agent), agent = NULL;
	if(manager != NULL) connman_manager_free(manager), manager = NULL;
}

static void connman_service_started(GDBusConnection *conn, const gchar *name, const gchar *name_owner, gpointer user_data)
{
	/* We just need one manager instance that stays throughout the lifetime
           of this daemon. Only its technologies and services lists are updated
	   whenever the corresponding signals are received */
	manager = connman_manager_new();
	if(NULL == manager)
		return;

	agent = connman_agent_new();
	if (NULL == agent)
	{
		connman_manager_free(manager);
		manager = NULL;
		return;
	}

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
}

/**
 * com.palm.wifi service Luna Method Table
 */

static LSMethod wifi_methods[] = {
    { LUNA_METHOD_GETPROFILELIST,	handle_get_profilelist_command },
    { LUNA_METHOD_GETPROFILE,		handle_get_profile_command },
    { LUNA_METHOD_SETSTATE,		handle_set_state_command },
    { LUNA_METHOD_CONNECT,		handle_connect_command },
    { LUNA_METHOD_FINDNETWORKS,		handle_findnetworks_command },
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
		WCA_LOG_FATAL("LSRegister() private returned error");
		goto Exit;
	}

	if (LSRegisterPubPriv(WIFI_LUNA_SERVICE_NAME, &pLsPublicHandle, true, &lserror) == false)
	{
		WCA_LOG_FATAL("LSRegister() public returned error");
		goto Exit;
	}

	if (LSRegisterCategory(pLsHandle, NULL, wifi_methods, NULL, NULL, &lserror) == false)
	{
		WCA_LOG_FATAL("LSRegisterCategory() returned error");
		goto Exit;
	}

	if (LSGmainAttach(pLsHandle, mainloop, &lserror) == false)
	{
		WCA_LOG_FATAL("LSGmainAttach() private returned error");
		goto Exit;
	}

	if (LSGmainAttach(pLsPublicHandle, mainloop, &lserror) == false)
	{
		WCA_LOG_FATAL("LSGmainAttach() public returned error");
		goto Exit;
	}

	g_type_init();

        g_bus_watch_name(G_BUS_TYPE_SYSTEM, "net.connman", G_BUS_NAME_WATCHER_FLAGS_NONE, connman_service_started, connman_service_stopped, NULL, NULL);

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
