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
 * @file connman_manager.c
 *
 * @brief Connman manager interface
 *
 */

#include "connman_manager.h"

/**
 * @brief  Retrieve all the properties of the given manager instance
 *
 * @param  manager
 *
 */

static GVariant *connman_manager_get_properties(connman_manager_t *manager)
{
	if(NULL == manager)
		return NULL;

	GError *error = NULL;
	GVariant *ret;

	connman_interface_manager_call_get_properties_sync(manager->remote,
						 &ret, NULL, &error);
	if (error)
	{
		g_error("%s", error->message);
		g_error_free(error);
		return NULL;
	}

	return ret;
}


static connman_service_t *find_service_from_path(GSList *service_list, const gchar *path)
{
	GSList *iter;

	for (iter = service_list; NULL != iter; iter = iter->next)
	{
		connman_service_t *service = (connman_service_t *)(iter->data);

		if (g_str_equal(service->path, path))
			return service;
	}
	return NULL;
}

/**
 * @brief  Get the path from the variant argument and get the service
 * in the manager's list matching the path in the variant
 *
 * @param  manager
 * @param  service_v
 *
 */


static connman_service_t *find_service_from_props(connman_manager_t *manager,
			GVariant	*service_v)
{
	if(NULL == manager || NULL == service_v)
		return NULL;

	GVariant *o = g_variant_get_child_value(service_v, 0);
	const gchar *path = g_variant_get_string(o, NULL);

	connman_service_t *service = NULL;
	service = find_service_from_path(manager->wifi_services, path);
	if(NULL != service)
		return service;

	service = find_service_from_path(manager->wired_services, path);
	return service;
}

static connman_technology_t *find_technology_by_path(connman_manager_t *manager,
			gchar *path)
{
	if(NULL == manager || NULL == path)
		return NULL;

	GSList *iter;

	for (iter = manager->technologies; NULL != iter; iter = iter->next)
	{
		connman_technology_t *technology = (connman_technology_t *)(iter->data);

		if (g_str_equal(technology->path, path))
		{
			return technology;
		}
	}

	return NULL;
}

/**
 * @brief  Check if the given service's "Ethernet" properties matches system's wifi/wired interface
 *
 * @param  service_v
 *
 */

static gboolean service_on_configured_iface(GVariant	*service_v)
{
	if(NULL == service_v)
		return FALSE;

	GVariant *properties = g_variant_get_child_value(service_v, 1);
	gsize i;

	for (i = 0; i < g_variant_n_children(properties); i++)
	{
		GVariant *property = g_variant_get_child_value(properties, i);
		GVariant *key_v = g_variant_get_child_value(property, 0);
		const gchar *key = g_variant_get_string(key_v, NULL);

		if (g_str_equal(key, "Ethernet"))
		{
			GVariant *v = g_variant_get_child_value(property, 1);
			GVariant *va = g_variant_get_child_value(v, 0);
			gsize j;
			for(j = 0; j < g_variant_n_children(va); j++)
		  	{
				GVariant *ethernet = g_variant_get_child_value(va, j);
				GVariant *ekey_v = g_variant_get_child_value(ethernet, 0);
				const gchar *ekey = g_variant_get_string(ekey_v, NULL);

				if(g_str_equal(ekey, "Interface"))
				{
					GVariant *ifacev = g_variant_get_child_value(ethernet, 1);
					GVariant *ifaceva = g_variant_get_variant(ifacev);
					const gchar *iface = g_variant_get_string(ifaceva, NULL);
					if(g_str_equal(iface,CONNMAN_WIFI_INTERFACE_NAME) ||
						g_str_equal(iface,CONNMAN_WIRED_INTERFACE_NAME))
						return TRUE;
					else
						return FALSE;
				}
		  	}
		}
	}
	return FALSE;
}

/**
 * @brief Compare the signal strengths of services and sort the list based on decreasing
 * signal strength. However the hidden service (if any) will always be put at the end of the list.
 */ 

static gint compare_signal_strength(connman_service_t *service1, connman_service_t *service2)
{
	if(service2->name == NULL) 
		return -1;	// let the hidden service be added to the list
				// after all non-hidden services
	else if(service1->name == NULL)
		return 1;	// insert non-hidden service2 before hidden service1
	return (service2->strength - service1->strength);
}

static add_service_to_list(connman_manager_t *manager, connman_service_t *service)
{
	if(connman_service_type_wifi(service))
	{
		manager->wifi_services = g_slist_insert_sorted(manager->wifi_services, service, compare_signal_strength);
	}
	else if(connman_service_type_ethernet(service))
	{
		manager->wired_services = g_slist_append(manager->wired_services, service);
	}
}

/**
 * @brief Go through the list of services in the "services" parameter and if the service
 * is already present in the manager's list , update its properties, and if not , add it
 * as a new service.
 * Return TRUE only if any service is updated or added, return FALSE otherwise
 *
 */

static gboolean connman_manager_update_services(connman_manager_t *manager, GVariant *services)
{
	if(NULL == manager || NULL == services)
		return FALSE;

	gsize i;
	gboolean ret = FALSE;

	for (i = 0; i < g_variant_n_children(services); i++)
	{
		GVariant *service_v = g_variant_get_child_value(services, i);
		connman_service_t *service;

		if(service_on_configured_iface(service_v))
		{
			service = find_service_from_props(manager, service_v);
			if(NULL != service)
			{		
				g_message("Updating service %s",service->name);
				connman_service_update_properties(service, service_v);
			}
			else
			{
				service = connman_service_new(service_v);
				g_message("Adding service %s",service->name);
				add_service_to_list(manager, service);
			}
			ret = TRUE;
		}
	}
	return ret;
}

/**
 * @brief Remove services from the given list
 */

static gboolean remove_services_from_list(GSList **service_list, gchar **services_removed)
{
	GSList *iter, *remove_list = NULL;
	gboolean ret = FALSE;

	/* look for removed services */
	while(NULL != *services_removed)
	{
		for (iter = *service_list; NULL != iter; iter = iter->next)
		{
			connman_service_t *service = (connman_service_t *)(iter->data);

			if (g_str_equal(service->path, *services_removed))
			{
				g_message("Removing service : %s",service->name);
				remove_list = g_slist_append(remove_list, service);
				break;
    			}
		}
		*services_removed++;
	}

	/* 
	 * do the actual remove of services in an extra loop, so we don't
	 * alter the list we're walking
	 */
	for (iter = remove_list; NULL != iter; iter = iter->next)
	{
		connman_service_t *service = (connman_service_t *)(iter->data);
		*service_list = g_slist_remove_link(*service_list, g_slist_find(*service_list, service));
		connman_service_free(service, NULL);
		ret = TRUE;
	}

	return ret;
}

/**
 * @brief Remove all the services in the services_removed string array from the manager's services list
 * one by one and return TRUE only if atleast one service is removed, else return FALSE
 *
 */

static gboolean connman_manager_remove_old_services(connman_manager_t *manager, gchar **services_removed)
{
	if(NULL == manager || NULL == services_removed)
		return FALSE;

	gboolean wifi_services_removed = FALSE, wired_services_removed = FALSE;
	gchar ** services_removed_copy;

	services_removed_copy = services_removed;
	wifi_services_removed = remove_services_from_list(&manager->wifi_services, services_removed);

	services_removed = services_removed_copy;
	wired_services_removed = remove_services_from_list(&manager->wired_services, services_removed);

	return (wifi_services_removed | wired_services_removed);
}

/**
 * @brief  Free the manager's services list
 *
 * @param  manager
 *
 */

static void connman_manager_free_services(connman_manager_t *manager)
{
	if(NULL == manager)
		return;
	g_slist_foreach(manager->wifi_services, (GFunc) connman_service_free, NULL);
	g_slist_free(manager->wifi_services);
	manager->wifi_services = NULL;

	g_slist_foreach(manager->wired_services, (GFunc) connman_service_free, NULL);
	g_slist_free(manager->wired_services);
	manager->wired_services = NULL;
}

/**
 * @brief  Free the manager's technologies list
 *
 * @param  manager
 *
 */

static void connman_manager_free_technologies(connman_manager_t *manager)

{
	if(NULL == manager)
		return;
	g_slist_foreach(manager->technologies, (GFunc) connman_technology_free, NULL);
	g_slist_free(manager->technologies);
	manager->technologies = NULL;
}

/**
 * @brief  Retrieve all the services for the manager and add them to its list
 *
 * @param  manager
 *
 */

static gboolean connman_manager_add_services(connman_manager_t *manager)
{
	if(NULL == manager)
		return FALSE;
	
	GError *error = NULL;
	GVariant *services;
	gsize i;

	connman_interface_manager_call_get_services_sync(manager->remote,
					       &services, NULL, &error);
	if (error)
	{
		g_error("%s", error->message);
		g_error_free(error);
		return FALSE;
	}

	for (i = 0; i < g_variant_n_children(services); i++)
	{
		GVariant *service_v = g_variant_get_child_value(services, i);
		connman_service_t *service = find_service_from_props(manager, service_v);

		if(service == NULL)
		{
			if(service_on_configured_iface(service_v))
			{
				service = connman_service_new(service_v);
				g_message("Adding service %s",service->name);
				add_service_to_list(manager, service);
			}
		}
	}
	return TRUE;
}

/**
 * @brief  Retrieve all the technologies for the manager and add them to its list
 *
 * @param  manager
 *
 */

static gboolean connman_manager_add_technologies (connman_manager_t *manager)
{
	if(NULL == manager)
		return FALSE;
	
	GError *error = NULL;
	GVariant *technologies;
	gsize i;

	connman_interface_manager_call_get_technologies_sync(manager->remote,
					       &technologies, NULL, &error);
	if (error)
	{
		g_error("%s", error->message);
		g_error_free(error);
		return FALSE;
	}

	for (i = 0; i < g_variant_n_children(technologies); i++)
	{
		GVariant *technology_v = g_variant_get_child_value(technologies, i);
		connman_technology_t *technology;

		technology = connman_technology_new(technology_v);
		manager->technologies = g_slist_append(manager->technologies, technology);
	}

	return TRUE;
}

/**
 * @brief  Check if the manager is not in offline mode and available to 
 * enable network connections
 *
 * @param  manager
 *
 */

gboolean connman_manager_is_manager_available (connman_manager_t *manager)
{
	if(NULL == manager)
		return FALSE;
	
	GVariant *properties = connman_manager_get_properties(manager);
	gsize i;

	for (i = 0; i < g_variant_n_children(properties); i++)
	{
		GVariant *property = g_variant_get_child_value(properties, i);
		GVariant *key_v = g_variant_get_child_value(property, 0);
		const gchar *key = g_variant_get_string(key_v, NULL);
		if (g_str_equal(key, "OfflineMode"))
		{
	  		GVariant *v = g_variant_get_child_value(property, 1);
			GVariant *va = g_variant_get_variant(v);
			gboolean offline = g_variant_get_boolean(va);
		
          		return !offline;
		}
	}

	return FALSE;
}

/**
 * @brief  Check if the manager in online ( its state is set to 'online')
 *
 * @param  manager
 *
 */

gboolean connman_manager_is_manager_online (connman_manager_t *manager)
{
	if(NULL == manager)
		return FALSE;

	GVariant *properties = connman_manager_get_properties(manager);
	gsize i;

	for (i = 0; i < g_variant_n_children(properties); i++)
	{
		GVariant *property = g_variant_get_child_value(properties, i);
		GVariant *key_v = g_variant_get_child_value(property, 0);
		const gchar *key = g_variant_get_string(key_v, NULL);
		if (g_str_equal(key, "State"))
		{
			GVariant *v = g_variant_get_child_value(property, 1);
			GVariant *va = g_variant_get_variant(v);
			const gchar *state = g_variant_get_string(va, NULL);
			if(g_str_equal(state, "online"))
				return TRUE;
		}
	}

	return FALSE;
}

/**
 * @brief  Go through the manager's technologies list and get the wifi one
 *
 * @param  manager
 *
 */

connman_technology_t *connman_manager_find_wifi_technology (connman_manager_t *manager)
{
	if(NULL == manager)
		return NULL;

	GSList *iter;

	for (iter = manager->technologies; NULL != iter; iter = iter->next)
	{
		connman_technology_t *tech = (struct connman_technology *)(iter->data);

		if (g_str_equal("wifi", tech->type))
		{
			return tech;
		}
	}

	return NULL;
}

/**
 * @brief  Go through the manager's technologies list and get the ethernet one
 *
 * @param  manager
 *
 */

connman_technology_t *connman_manager_find_ethernet_technology (connman_manager_t *manager)
{
	if(NULL == manager)
		return NULL;

	GSList *iter;

	for (iter = manager->technologies; NULL != iter; iter = iter->next)
	{
		connman_technology_t *tech = (struct connman_technology *)(iter->data);

		if (g_str_equal("ethernet", tech->type))
		{
			return tech;
		}
	}

	return NULL;
}

/**
 * @brief  Go through the manager's services list and get the one which is in "association",
 * "configuration", "ready" or "online" state 
 *
 * @param  manager
 *
 */


connman_service_t *connman_manager_get_connected_service (connman_manager_t *manager)
{
	if(NULL == manager)
		return NULL;

	GSList *iter;
	for (iter = manager->wired_services; NULL != iter; iter = iter->next)
	{
		connman_service_t *service = (struct connman_service *)(iter->data);
		int service_state = connman_service_get_state(service->state);
		if(service_state == CONNMAN_SERVICE_STATE_ONLINE)
		{
			return service;
		}
	}

	for (iter = manager->wifi_services; NULL != iter; iter = iter->next)
	{
		connman_service_t *service = (struct connman_service *)(iter->data);
		if(NULL == service->state)
			continue;

		int service_state = connman_service_get_state(service->state);

		switch(service_state)
		{
			case  CONNMAN_SERVICE_STATE_ASSOCIATION:
			case  CONNMAN_SERVICE_STATE_CONFIGURATION:
			case  CONNMAN_SERVICE_STATE_READY:
			case  CONNMAN_SERVICE_STATE_ONLINE:
				return service;
			default:
				continue;
		}
	}
	return NULL;

}

/**
 * @brief  Callback for manager's "property_changed" signal
 *
 * @param  proxy
 * @param  property
 * @param  v
 * @param  manager
 *
 */

static void
property_changed_cb(ConnmanInterfaceManager *proxy,const gchar * property, GVariant *v,
	      connman_manager_t      *manager)
{
	GVariant *va = g_variant_get_child_value(v, 0);
	g_message("Manager property %s changed : %s",property, g_variant_get_string(va,NULL));
	if(NULL != manager->handle_property_change_fn)
		(manager->handle_property_change_fn)((gpointer)manager, property, v);
}


/**
 * @brief  Callback for manager's "technology_added" signal
 *
 * @param  proxy
 * @param  property
 * @param  v
 * @param  manager
 *
 */

static void
technology_added_cb(ConnmanInterfaceManager *proxy, gchar * path, GVariant *v,
	      connman_manager_t      *manager)
{
	g_message("Technology %s added", path);

	if(NULL == find_technology_by_path(manager,path))
	{
		GVariant *technology_v = g_variant_new("(o@a{sv})",path, v);
		connman_technology_t *technology = connman_technology_new(technology_v);
		g_message("Updating manager's technology list");
		manager->technologies = g_slist_append(manager->technologies, technology);
	}
}

/**
 * @brief  Callback for manager's "technology_removed" signal
 *
 * @param  manager
 *
 */

static void
technology_removed_cb(ConnmanInterfaceManager *proxy, gchar * path,
	      connman_manager_t      *manager)
{
	g_message("Technology removed");
	connman_technology_t *technology = find_technology_by_path(manager, path);
	if(NULL != technology)
	{
		manager->technologies = g_slist_remove_link(manager->technologies, g_slist_find(manager->technologies, technology));
		connman_technology_free(technology, NULL);
	}
}

/**
 * @brief  Callback for manager's "services_changed" signal
 *
 * @param  proxy
 * @param  property
 * @param  v
 * @param  manager
 *
 */

static void 
services_changed_cb(ConnmanInterfaceManager *proxy, GVariant *services_added, 
		gchar **services_removed, connman_manager_t *manager)
{
	g_message("Services_changed ");
	if(connman_manager_update_services(manager, services_added) ||
		connman_manager_remove_old_services(manager, services_removed))
	{
		if(NULL != manager->handle_services_change_fn)
			(manager->handle_services_change_fn)(manager);
	}
}


void connman_manager_register_property_changed_cb(connman_manager_t *manager, connman_property_changed_cb func)
{
	if(NULL == func)
		return;
	manager->handle_property_change_fn = func;
}

void connman_manager_register_services_changed_cb(connman_manager_t *manager, connman_services_changed_cb func)
{
	if(NULL == func)
		return;
	manager->handle_services_change_fn = func;
}


/**
 * @brief Register a agent instance on the specified dbus path with the manager
 *
 * @param DBus object path where the agents is available
 * @return TRUE, if agent was successfully registered with the manager, FALSE otherwise.
 **/

gboolean connman_manager_register_agent(connman_manager_t *manager, const gchar *path)
{
	GError *error = NULL;

	if (NULL == manager)
		return FALSE;

	connman_interface_manager_call_register_agent_sync(manager->remote,
		path, NULL, &error);
	if (error) {
		g_message("%s", error->message);
		g_error_free(error);
		return FALSE;
	}

	g_message("Registered agent successfully with connman");

	return TRUE;
}

/**
 * @brief Unegister a agent instance on the specified dbus path from the manager
 *
 * @param DBus object path where the agents is available
 * @return TRUE, if agent was successfully unregistered from the manager, FALSE otherwise.
 **/

gboolean connman_manager_unregister_agent(connman_manager_t *manager, const gchar *path)
{
	GError *error;

	if (NULL == manager)
		return FALSE;

	connman_interface_manager_call_unregister_agent_sync(manager->remote,
		path, NULL, &error);
	if (error) {
		g_error("%s", error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

/**
 * @brief  Initialize a new manager instance and update its services and technologies list
 *
 */

connman_manager_t *connman_manager_new (void)
{
	GError *error = NULL;
	connman_manager_t *manager = g_new0(connman_manager_t, 1);
	if(manager == NULL)
	{
		g_error("Out of memory !!!");
		return NULL;
	}

	manager->wifi_services = NULL;
	manager->wired_services = NULL;
	manager->technologies = NULL;

	manager->remote = connman_interface_manager_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
								G_DBUS_PROXY_FLAGS_NONE,
								"net.connman", "/",
								NULL,
								&error);
	if (error)
	{
		g_error("%s", error->message);
		g_error_free(error);
		g_free(manager);
		return NULL;
	}
	
	manager->handle_property_change_fn = manager->handle_services_change_fn = NULL;
	
	g_signal_connect(G_OBJECT(manager->remote), "property-changed",
		   G_CALLBACK(property_changed_cb), manager);

	g_signal_connect(G_OBJECT(manager->remote), "technology-added",
		   G_CALLBACK(technology_added_cb), manager);

	g_signal_connect(G_OBJECT(manager->remote), "technology-removed",
		   G_CALLBACK(technology_removed_cb), manager);

	g_signal_connect(G_OBJECT(manager->remote), "services-changed",
		   G_CALLBACK(services_changed_cb), manager);


	connman_manager_add_technologies(manager);
	connman_manager_add_services(manager);

	g_message("%d wifi services", g_slist_length(manager->wifi_services));
	g_message("%d wired services", g_slist_length(manager->wired_services));
	g_message("%d technologies", g_slist_length(manager->technologies));

	return manager;
}

/**
 * @brief  Free the manager instance
 *
 * @param  manager
 *
 */

void connman_manager_free (connman_manager_t *manager)
{
	if(NULL == manager)
		return;

	connman_manager_free_services(manager);
	connman_manager_free_technologies(manager);

	g_free(manager);
	manager = NULL;
}
