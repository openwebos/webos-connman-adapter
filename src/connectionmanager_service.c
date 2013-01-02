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
 * @file  connectionmanager_service.c
 *
 * @brief Implements all of the com.palm.connectionmanager methods using connman APIs
 * in the backend
 *
 */


#include <glib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <pbnjson.h>

#include "common.h"
#include "connman_manager.h"
#include "connectionmanager_service.h"
#include "lunaservice_utils.h"

static LSHandle *pLsHandle, *pLsPublicHandle;

/**
 * @brief Fill in information about the system's wifi status
 *
 * @param wifi_status
 */

static void update_wifi_status(jvalue_ref *wifi_status)
{
	if(NULL == wifi_status)
		return;

	/* Get the service which is connecting or already in connected state */
	connman_service_t *connected_service = connman_manager_get_connected_service(manager);
	if((connected_service != NULL) && connman_service_type_wifi(connected_service))
	{
		int connman_state = 0;

		if(connected_service->state != NULL)
		{
			connman_state = connman_service_get_state(connected_service->state);
			if(connman_state == CONNMAN_SERVICE_STATE_ONLINE
				|| connman_state == CONNMAN_SERVICE_STATE_READY)
			{
				connman_service_get_ipinfo(connected_service);

				jobject_put(*wifi_status, J_CSTR_TO_JVAL("state"), jstring_create("connected"));
				if(NULL != connected_service->ipinfo.ipv4.address)
					jobject_put(*wifi_status, J_CSTR_TO_JVAL("ipAddress"), jstring_create(connected_service->ipinfo.ipv4.address));
				if(NULL != connected_service->ipinfo.iface)
					jobject_put(*wifi_status, J_CSTR_TO_JVAL("interfaceName"), jstring_create(connected_service->ipinfo.iface));
				if(NULL != connected_service->name)
					jobject_put(*wifi_status, J_CSTR_TO_JVAL("ssid"), jstring_create(connected_service->name));
				//TODO Need to implement function to check if the system can connect to internet
				jobject_put(*wifi_status, J_CSTR_TO_JVAL("onInternet"), jstring_create("yes"));
				jobject_put(*wifi_status, J_CSTR_TO_JVAL("isWakeOnWifiEnabled"), jboolean_create(false));
				return;
			}
		}
	}

	jobject_put(*wifi_status, J_CSTR_TO_JVAL("state"), jstring_create("disconnected"));
}

/**
 * @brief Fill in information about the system's wired status
 *
 * @param wired_status
 */

static void update_wired_status(jvalue_ref *wired_status)
{
	if(NULL == wired_status)
		return;

	/* Get the service which is connecting or already in connected state */
	connman_service_t *connected_service = connman_manager_get_connected_service(manager);
	if((connected_service != NULL) && connman_service_type_ethernet(connected_service))
	{
		int connman_state = 0;

		if(connected_service->state != NULL)
		{
			connman_state = connman_service_get_state(connected_service->state);

			if(connman_state == CONNMAN_SERVICE_STATE_ONLINE)
			{
				connman_service_get_ipinfo(connected_service);

				jobject_put(*wired_status, J_CSTR_TO_JVAL("state"), jstring_create("connected"));
				if(NULL != connected_service->ipinfo.ipv4.address)
					jobject_put(*wired_status, J_CSTR_TO_JVAL("ipAddress"), jstring_create(connected_service->ipinfo.ipv4.address));
				if(NULL != connected_service->ipinfo.iface)
					jobject_put(*wired_status, J_CSTR_TO_JVAL("interfaceName"), jstring_create(connected_service->ipinfo.iface));
				//TODO Need to implement function to check if the system can connect to internet
				jobject_put(*wired_status, J_CSTR_TO_JVAL("onInternet"), jstring_create("yes"));
				return;
			}
		}
	}
	jobject_put(*wired_status, J_CSTR_TO_JVAL("state"), jstring_create("disconnected"));
}

/**
 * @brief Fill in all the status information to be sent with 'getstatus' method
 */

static void send_connection_status(jvalue_ref *reply)
{
        if(NULL == reply)
                return;
	jobject_put(*reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	gboolean online = connman_manager_is_manager_online(manager);
	jobject_put(*reply, J_CSTR_TO_JVAL("isInternetConnectionAvailable"), jboolean_create(online));

	jvalue_ref wifi_status = jobject_create();
	jvalue_ref wired_status = jobject_create();

	update_wifi_status(&wifi_status);
	update_wired_status(&wired_status);

	jobject_put(*reply, J_CSTR_TO_JVAL("wifi"), wifi_status);
	jobject_put(*reply, J_CSTR_TO_JVAL("wired"), wired_status);
}


/**
 *  @brief Callback function registered with connman manager whenever any of its properties change
 *
 */

void connectionmanager_send_status(void)
{
	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	send_connection_status(&reply);

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);
		LSError lserror;
		LSErrorInit(&lserror);
		g_message("Sending payload %s",payload);
		if (!LSSubscriptionPost(pLsHandle, "/", "getstatus", payload, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
		jschema_release(&response_schema);
	}
	j_release(&reply);
}


/**
 *  @brief Handler for "getstatus" command.
 *  Get the current network connection status on the system, both wifi and wired
 *
 *  JSON format:
 *
 *  luna://com.palm.connectionmanager/getstatus {}
 *  luna://com.palm.connectionmanager/getstatus {"subscribe":true}
 *
 *  @param sh
 *  @param message
 *  @param context
 */

static bool handle_get_status_command(LSHandle* sh, LSMessage *message, void* context)
{
	if(!connman_status_check(manager, sh, message))
		return true;

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

	send_connection_status(&reply);

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(!response_schema)
	{
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
 * @brief Loop through the manager's wifi services and match the one with the given ssid
 * If 'ssid' is NULL then return the wired service on the system
 *
 * @param ssid
 */


static connman_service_t *get_connman_service(gchar *ssid)
{
	if(NULL != ssid)
	{
		GSList *ap;

		/* Look up for the service with the given ssid */
		for (ap = manager->wifi_services; ap; ap = ap->next)
		{
			connman_service_t *service = (connman_service_t *)(ap->data);
			if((NULL != service->name) && g_str_equal(service->name, ssid))
			{
				return service;
			}
		}
	}
	else
	{
		GSList *ap;
		/* Return the first wired service (there will be just one on most systems) */
		for (ap = manager->wired_services; ap; ap = ap->next)
		{
			connman_service_t *service = (connman_service_t *)(ap->data);
			return service;

		}

	}
	return NULL;
}


/**
 *  @brief Handler for "setipv4" command.
 *  Change the ipv4 properties for the given wifi ssid or for the wired connection
 *
 *  JSON format:
 *
 *  luna://com.palm.connectionmanager/setipv4 '{"method":"<dhcp/manual>","address":"<new address>",
 *		"netmask":"<new netmask>","gateway":<"new gateway">,"ssid":"<ssid value>"}'
 *
 *  @param sh
 *  @param message
 *  @param context
 */


static bool handle_set_ipv4_command(LSHandle *sh, LSMessage *message, void* context)
{
	if(!connman_status_check(manager, sh, message))
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
		goto Exit;
	}

	jvalue_ref ssidObj = {0}, methodObj = {0}, addressObj = {0}, netmaskObj = {0}, gatewayObj = {0};
	ipv4info_t ipv4 = {0};
	gchar *ssid = NULL;

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("method"), &methodObj))
	{
		raw_buffer method_buf = jstring_get(methodObj);
		ipv4.method = g_strdup(method_buf.m_str);
	}
	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("address"), &addressObj))
	{
		raw_buffer address_buf = jstring_get(addressObj);
		ipv4.address = g_strdup(address_buf.m_str);
	}
	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("netmask"), &netmaskObj))
	{
		raw_buffer netmask_buf = jstring_get(netmaskObj);
		ipv4.netmask = g_strdup(netmask_buf.m_str);
	}
	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("gateway"), &gatewayObj))
	{
		raw_buffer gateway_buf = jstring_get(gatewayObj);
		ipv4.gateway = g_strdup(gateway_buf.m_str);
	}
	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer ssid_buf = jstring_get(ssidObj);
		ssid = g_strdup(ssid_buf.m_str);
	}

	connman_service_t *service = get_connman_service(ssid);
	if(NULL != service)
	{
		if(connman_service_set_ipv4(service, &ipv4))
			LSMessageReplySuccess(sh, message);
		else
			LSMessageReplyErrorUnknown(sh, message);
		goto Exit;
	}
	else
		LSMessageReplyCustomError(sh, message, "Network not found");


Exit:
	g_free(ipv4.method);
	g_free(ipv4.address);
	g_free(ipv4.netmask);
	g_free(ipv4.gateway);
	g_free(ssid);
	j_release(&parsedObj);
	return true;
}

/**
 *  @brief Handler for "setdns" command.
 *  Change the dns servers for the given wifi ssid or for the wired connection
 *
 *  JSON format:
 *
 *  luna://com.palm.connectionmanager/setipv4 '{"dns":"[list of dns servers]","ssid":"<ssid value>"}'
 *
 *  @param sh
 *  @param message
 *  @param context
 */


static bool handle_set_dns_command(LSHandle *sh, LSMessage *message, void* context)
{
	if(!connman_status_check(manager, sh, message))
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
		goto Exit;
	}

	jvalue_ref ssidObj = {0}, dnsObj = {0};
	GStrv dns;
	gchar *ssid;

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("dns"), &dnsObj))
	{
		int i, dns_arrsize = jarray_size(dnsObj);
		dns = g_new0(GStrv, 1);
		for(i = 0; i < dns_arrsize; i++)
		{
			raw_buffer dns_buf = jstring_get(jarray_get(dnsObj, i));
			dns[i] = g_strdup(dns_buf.m_str);
		}
	}

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer ssid_buf = jstring_get(ssidObj);
		ssid = g_strdup(ssid_buf.m_str);
	}

	connman_service_t *service = get_connman_service(ssid);
	if(NULL != service)
	{
		if(connman_service_set_nameservers(service, dns))
			LSMessageReplySuccess(sh, message);
		else
			LSMessageReplyErrorUnknown(sh, message);
		goto Exit;
	}
	else
		LSMessageReplyCustomError(sh, message, "No connected network");
Exit:
	g_strfreev(dns);
	g_free(ssid);
	j_release(&parsedObj);
	return true;
}


/**
 * com.palm.connectionmanager service Luna Method Table
 */

static LSMethod connectionmanager_methods[] = {
    { LUNA_METHOD_GETSTATUS,		handle_get_status_command },
    { LUNA_METHOD_SETIPV4,		handle_set_ipv4_command },
    { LUNA_METHOD_SETDNS,		handle_set_dns_command },
    { },
};

/**
 *  @brief Initialize com.palm.connectionmanager service and all of its methods
 *  Also initialize a manager instance
 */

int initialize_connectionmanager_ls2_calls( GMainLoop *mainloop )
{
	LSError lserror;
	LSErrorInit (&lserror);
	pLsHandle       = NULL;
	pLsPublicHandle = NULL;

	if(NULL == mainloop)
		goto Exit;

	if (LSRegisterPubPriv(CONNECTIONMANAGER_LUNA_SERVICE_NAME, &pLsHandle, false, &lserror) == false)
	{
		g_error("LSRegister() private returned error");
		goto Exit;
	}

	if (LSRegisterPubPriv(CONNECTIONMANAGER_LUNA_SERVICE_NAME, &pLsPublicHandle, true, &lserror) == false)
	{
		g_error("LSRegister() public returned error");
		goto Exit;
	}

	if (LSRegisterCategory(pLsHandle, NULL, connectionmanager_methods, NULL, NULL, &lserror) == false)
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
