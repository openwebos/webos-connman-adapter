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


#include "connman-interface.h"
#include "connman_manager.h"

static GVariant *connman_manager_get_properties(connman_manager_t *manager)
{
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


static gboolean service_already_added(connman_manager_t *manager,
			GVariant	*service_v)
{
	GSList *iter;
	GVariant *o = g_variant_get_child_value(service_v, 0);
	const gchar *path = g_variant_get_string(o, NULL);

	for (iter = manager->services; iter; iter = iter->next)
	{
		connman_service_t *service = (connman_service_t *)(iter->data);

		if (g_str_equal(service->path, path))
			return TRUE;
	}

	return FALSE;
}


static gboolean service_on_wifi_iface(GVariant	*service_v)
{
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
					if(g_str_equal(iface,CONNMAN_WIFI_INTERACE_NAME))
						return TRUE;
					else
						return FALSE;
				}
		  	}
		}
	}
	return FALSE;
}


// TODO: The "services_changed" signal needs better handling, so that instead of refetching all services
// only services that have been added, changed or removed should be handled.

#if 0

static void connman_manager_update_services(connman_manager_t *manager, GVariant *services)
{
	gsize i;
	GSList *iter, *remove_list;

	for (i = 0; i < g_variant_n_children(services); i++)
	{
		GVariant *service_v = g_variant_get_child_value(services, i);
		connman_service_t *service;

		if(service_on_wifi_iface(service_v))
		{
			if(service_already_added(manager, service_v))
			{		
				remove_list = g_slist_append(remove_list, service);
			}
			service = connman_service_new(service_v);
			g_message("Adding service %s",service->name);
			manager->services = g_slist_append(manager->services, service);
		}
	}

	for(iter = remove_list; iter; iter = iter->next)
	{
		connman_service_t *service = (connman_service_t *)(iter->data);
		manager->services = g_slist_remove(manager->services, service);
		connman_service_free(service, NULL);
	}

}

static void connman_manager_remove_old_services(connman_manager_t *manager, GVariant *services)
{
	GSList *iter, *remove_list;
	gsize i;
	/* look for removed services */
	for (iter = manager->services; iter; iter = iter->next)
	{
		connman_service_t *service = (connman_service_t *)(iter->data);
		gboolean found = FALSE;

		for (i = 0; i < g_variant_n_children(services); i++)
		{
			GVariant *service_v = g_variant_get_child_value(services, i);
			GVariant *o = g_variant_get_child_value(service_v, 0);
			const gchar *path = g_variant_get_string(o, NULL);

			g_message("Removing service %s",path);
			if (g_str_equal(service->path, path))
			{
				found = TRUE;
				break;
    			}
		}

	if (!found)
		remove_list = g_slist_append(remove_list, service);

	}

	/* 
	 * do the actual remove of services in an extra loop, so we don't
	 * alter the list we're walking
	 */
	for (iter = remove_list; iter; iter = iter->next)
	{
		connman_service_t *service = (connman_service_t *)(iter->data);
		manager->services = g_slist_remove_link(manager->services, service);
		connman_service_free(service, NULL);
	}
}
#endif


static void connman_manager_free_services(connman_manager_t *manager)
{
	g_slist_foreach(manager->services, (GFunc) connman_service_free, NULL);
	g_slist_free(manager->services);
	manager->services = NULL;
}


static void connman_manager_free_technologies(connman_manager_t *manager)
{
	g_slist_foreach(manager->technologies, (GFunc) connman_technology_free, NULL);
	g_slist_free(manager->technologies);
	manager->technologies = NULL;
}

static gboolean connman_manager_add_services(connman_manager_t *manager)
{
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
		connman_service_t *service;

		if(!service_already_added(manager, service_v))
		{
			if(service_on_wifi_iface(service_v))
			{
				service = connman_service_new(service_v);
				g_message("Adding service %s",service->name);
				manager->services = g_slist_append(manager->services, service);
			}
		}
	}
	return TRUE;
}


static gboolean connman_manager_add_technologies (connman_manager_t *manager)
{
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

gboolean connman_manager_is_manager_available (connman_manager_t *manager)
{
	GVariant *properties = connman_manager_get_properties(manager);
	gsize i;

	for (i = 0; i < g_variant_n_children(properties); i++)
	{
		GVariant *property = g_variant_get_child_value(properties, i);
		GVariant *key_v = g_variant_get_child_value(property, 0);
		const gchar *key = g_variant_get_string(key_v, NULL);

		if (g_str_equal(key, "offlineMode"))
		{
	  		GVariant *v = g_variant_get_child_value(property, 1);
			GVariant *va = g_variant_get_variant(v);
			gboolean offline = g_variant_get_boolean(va);

          		return !offline;
		}
	}

	return FALSE;
}

connman_technology_t *connman_manager_find_wifi_technology (connman_manager_t *manager)
{

	GSList *iter;

	for (iter = manager->technologies; iter; iter = iter->next)
	{
		connman_technology_t *tech = (struct connman_technology *)(iter->data);

		if (g_str_equal("wifi", tech->type))
			return tech;
	}

	return NULL;
}


connman_service_t *connman_manager_get_connected_service (connman_manager_t *manager)
{
	GSList *iter;

	for (iter = manager->services; iter; iter = iter->next)
	{
		connman_service_t *service = (struct connman_service *)(iter->data);
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

void connman_manager_update_services(connman_manager_t *manager)
{
	if(manager->services_updated)
	{
		connman_manager_free_services(manager);
		connman_manager_add_services(manager);
		manager->services_updated = FALSE;
	}
}

void connman_manager_update_technologies(connman_manager_t *manager)
{
	if(manager->technologies_updated)
	{
		connman_manager_free_technologies(manager);
		connman_manager_add_technologies(manager);
		manager->technologies_updated = FALSE;
	}
}


//TODO Use property_changed signal for "com.palm.wifi/getstatus" subscriptions

static void
property_changed_cb(ConnmanInterfaceManager *proxy,const gchar * property, GVariant *v,
	      connman_manager_t      *manager)
{
	GVariant *va = g_variant_get_child_value(v, 0);
	g_message("Manager property %s changed : %s",property, g_variant_get_string(va,NULL));
}

static void
technology_added_cb(ConnmanInterfaceManager *proxy,const gchar * path, GVariant *v,
	      connman_manager_t      *manager)
{
	g_message("Technology %s added", path);
	manager->technologies_updated = TRUE;
}

static void
technology_removed_cb(ConnmanInterfaceManager *proxy, GVariant *v,
	      connman_manager_t      *manager)
{
	g_message("Technology removed");
	manager->technologies_updated = TRUE;
}

static void 
services_changed_cb(ConnmanInterfaceManager *proxy, GVariant *services_added, 
		GVariant *services_removed, connman_manager_t *manager)
{
	g_message("Services_changed");
	manager->services_updated = TRUE;
}

connman_manager_t *connman_manager_new (void)
{
	GError *error = NULL;
	connman_manager_t *manager = malloc(sizeof(connman_manager_t));
	if(manager == NULL)
	{
		g_error("Out of memory !!!");
		return NULL;
	}

	manager->services = NULL;
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
		return NULL;
	}
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

	manager->services_updated = manager->technologies_updated = FALSE;

	g_message("%d services", g_slist_length(manager->services));
	g_message("%d technologies", g_slist_length(manager->technologies));

	return manager;
}

void connman_manager_free (connman_manager_t *manager)
{
	if(manager == NULL)
		return;

	connman_manager_free_services(manager);
	connman_manager_free_technologies(manager);

	free(manager);
	manager = NULL;
}
