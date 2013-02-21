/* @@@LICENSE
*
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
 * @file connman_agent.c
 *
 * @brief Connman agent interface
 *
 */

#include <string.h>

#include "connman_agent.h"
#include "logging.h"

#define AGENT_DBUS_PATH			"/"
#define AGENT_ERROR_CANCELED	"net.connman.Agent.Error.Canceled"

struct connman_agent {
	ConnmanInterfaceAgent *interface;
	gchar *path;
	connman_agent_registered_cb registered_cb;
	gpointer registered_data;
	connman_agent_request_input_cb request_input_cb;
	gpointer request_input_data;
	connman_agent_report_error_cb report_error_cb;
	gpointer report_error_data;
	guint bus_id;
};

static gboolean request_input_cb(ConnmanInterfaceAgent *interface,
								 GDBusMethodInvocation *invocation,
								 const gchar *path,
								 GVariant *fields,
								 gpointer user_data)
{
	connman_agent_t *agent = user_data;
	GVariant *response = NULL;

	if (agent->request_input_cb == NULL) {
		g_dbus_method_invocation_return_dbus_error(invocation, AGENT_ERROR_CANCELED,
			"No handler available");
	}
	else {
		response = agent->request_input_cb(fields, agent->request_input_data);
		connman_interface_agent_complete_request_input(agent->interface, invocation, response);
	}

	return TRUE;
}

static gboolean report_error_cb(ConnmanInterfaceAgent *interface,
								GDBusMethodInvocation *invocation,
								const char *path,
								const char *error_message,
								gpointer user_data)
{
	connman_agent_t *agent = user_data;

	if (agent->report_error_cb == NULL) {
		g_dbus_method_invocation_return_dbus_error(invocation, AGENT_ERROR_CANCELED,
			"No handler available");
	}
	else {
		agent->report_error_cb(error_message, agent->report_error_data);
	}

	return TRUE;
}

static void bus_acquired_cb(GDBusConnection *connection, const gchar *name, gpointer user_data)
{
	GError *error = NULL;
	connman_agent_t *agent = user_data;

	agent->path = g_strdup(AGENT_DBUS_PATH);
	agent->interface = connman_interface_agent_skeleton_new();

	g_signal_connect(agent->interface, "handle-request-input", G_CALLBACK(request_input_cb), agent);
	g_signal_connect(agent->interface, "handle-report-error", G_CALLBACK(report_error_cb), agent);

	error = NULL;
	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(agent->interface), connection,
										  agent->path, &error))
	{
		WCA_LOG_CRITICAL("Could not export agent object: %s", error->message);
		g_error_free(error);
	}

	if (agent->registered_cb != NULL) {
		agent->registered_cb(agent->registered_data);
	}

	WCA_LOG_DEBUG("Agent successfully exported");
}

connman_agent_t* connman_agent_new(void)
{
	connman_agent_t *agent;

	agent = g_new0(connman_agent_t, 1);
	if (agent == NULL)
	{
		WCA_LOG_FATAL("Out of memory !!!");
		return NULL;
	}

	agent->bus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM, "com.palm.wifi", G_BUS_NAME_OWNER_FLAGS_NONE,
				bus_acquired_cb, NULL, NULL, agent, NULL);

	return agent;
}

void connman_agent_free(connman_agent_t *agent)
{
	if (agent == NULL)
		return;

	g_bus_unown_name(agent->bus_id);

	if (agent->path)
		g_free(agent->path);

	if (agent->interface)
		g_free(agent->interface);

	g_free(agent);
}

gchar* connman_agent_get_path(connman_agent_t *agent)
{
	if (agent == NULL)
		return NULL;

	return agent->path;
}

void connman_agent_set_registered_callback(connman_agent_t *agent, connman_agent_registered_cb cb, gpointer user_data)
{
	if (agent == NULL)
		return;

	agent->registered_cb = cb;
	agent->registered_data = user_data;
}

void connman_agent_set_request_input_callback(connman_agent_t *agent, connman_agent_request_input_cb cb, gpointer user_data)
{
	if (agent == NULL)
		return;

	agent->request_input_cb = cb;
	agent->request_input_data = user_data;
}

void connman_agent_set_report_error_callback(connman_agent_t *agent, connman_agent_report_error_cb cb, gpointer user_data)
{
	if (agent == NULL)
		return;

	agent->report_error_cb = cb;
	agent->report_error_data = user_data;
}
