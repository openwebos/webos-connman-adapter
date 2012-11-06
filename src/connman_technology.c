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

#include "connman-interface.h"
#include "connman_technology.h"

/**
 * @brief  Power on/off the given technology  
 *
 * @param  technology
 * @param  state
 *
 */

gboolean connman_technology_set_powered(connman_technology_t *technology, gboolean state)
{
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
 * @brief  Scan the network for available services
 *
 * @param  technology
 *
 */

gboolean connman_technology_scan_network(connman_technology_t *technology)
{
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
 * @brief  Create a new technology instance and set its properties
 *
 * @param  variant
 *
 */

connman_technology_t *connman_technology_new(GVariant *variant)
{
	connman_technology_t *technology = malloc(sizeof(connman_technology_t));
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
		return NULL;
	}


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
 * @brief  Free the technology instance
 *
 * @param  data
 * @param  user_data
 *
 */

void connman_technology_free(gpointer data, gpointer user_data)
{
	connman_technology_t *technology = (connman_technology_t *)data;

	if(technology == NULL)
		return;
	
	if(technology->path)
		g_free(technology->path);
	if(technology->type)
		g_free(technology->type);
	if(technology->name)
		g_free(technology->name);

	free(technology);
	technology = NULL;

}
