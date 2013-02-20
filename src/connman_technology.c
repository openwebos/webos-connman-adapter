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
 * @file connman_technology.c
 *
 * @brief Connman technology interface
 *
 */

#include "connman_technology.h"

/**
 * Power on/off the given technology (see header for API details)
 */

gboolean connman_technology_set_powered(connman_technology_t *technology, gboolean state)
{
	if(NULL == technology)
		return FALSE;

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
						  "Powered",
						  g_variant_new_variant(g_variant_new_boolean(state)),
						  NULL, &error);
	if (error)
	{
		g_message("%s", error->message);
		g_error_free(error);
		return FALSE;
	}

	technology->powered = state;
	return TRUE;
}

/**
 * Scan the network for available services (see header for API details)
 */

gboolean connman_technology_scan_network(connman_technology_t *technology)
{
	if(NULL == technology)
		return FALSE;

	GError *error = NULL;

	connman_interface_technology_call_scan_sync(technology->remote, NULL, &error);
	if (error)
	{
		g_message("%s", error->message);
		g_error_free(error);
		return FALSE;
	}
	return TRUE;
}

/**
 * Callback for technology's "property_changed" signal
 */

static void
property_changed_cb(ConnmanInterfaceTechnology *proxy,const gchar * property, GVariant *v,
              connman_technology_t      *technology)
{
	if(NULL != technology->handle_property_change_fn)
                (technology->handle_property_change_fn)((gpointer)technology, property, v);
}


/**
 * Register for technology's "properties_changed" signal, calling the provided function whenever the callback function
 * for the signal is called (see header for API details)
 */

void connman_technology_register_property_changed_cb(connman_technology_t *technology, connman_property_changed_cb func)
{
	if(NULL == func)
		return;

	technology->handle_property_change_fn = func;
}


/**
 * Create a new technology instance and set its properties (see header fpr API details)
 */

connman_technology_t *connman_technology_new(GVariant *variant)
{
	if(NULL == variant)
		return NULL;

	connman_technology_t *technology = g_new0(connman_technology_t, 1);
	if(technology == NULL)
	{
		g_error("Out of memory !!!");
		return NULL;
	}

	GVariant *technology_v = g_variant_get_child_value(variant, 0);
	GVariant *properties;
	gsize i;
	GError *error = NULL;

	technology->path = g_variant_dup_string(technology_v, NULL);

	technology->remote = connman_interface_technology_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
								G_DBUS_PROXY_FLAGS_NONE,
								"net.connman", 
								technology->path,
								NULL,
								&error);
	if (error)
	{
		g_error("%s", error->message);
		g_error_free(error);
		g_free(technology);
		return NULL;
	}

	technology->sighandler_id = g_signal_connect_data(G_OBJECT(technology->remote), "property-changed",
                   G_CALLBACK(property_changed_cb), technology, NULL, 0);


	properties = g_variant_get_child_value(variant, 1);

	for (i = 0; i < g_variant_n_children(properties); i++)
	{
		GVariant *property = g_variant_get_child_value(properties, i);
		GVariant *key_v = g_variant_get_child_value(property, 0);
		GVariant *val_v = g_variant_get_child_value(property, 1);
		GVariant *val = g_variant_get_variant(val_v);
		const gchar *key = g_variant_get_string(key_v, NULL);

		if (g_str_equal(key, "Type"))
			technology->type = g_variant_dup_string(val, NULL);

		else if (g_str_equal(key, "Name"))
			technology->name = g_variant_dup_string(val, NULL);

		else if (g_str_equal(key, "Powered"))
			technology->powered = g_variant_get_boolean(val);
	}

	return technology;
}

/**
 * Free the technology instance ( see header for API details)
 */

void connman_technology_free(gpointer data, gpointer user_data)
{
	connman_technology_t *technology = (connman_technology_t *)data;

	if(NULL == technology)
		return;
	
	g_free(technology->path);
	g_free(technology->type);
	g_free(technology->name);

	if(technology->sighandler_id)
		g_signal_handler_disconnect(G_OBJECT(technology->remote), technology->sighandler_id);
	technology->handle_property_change_fn = NULL;

	g_free(technology);
	technology = NULL;

}
