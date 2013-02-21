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
 * @file  wifi_setting.c
 *
 * @brief Functions for storing/loading wifi settings & profiles from luna-prefs
 *
 */

#include <glib.h>
#include <openssl/blowfish.h>
#include <lunaprefs.h>
#include <pbnjson.h>

#include "wifi_setting.h"
#include "wifi_service.h"
#include "wifi_profile.h"
#include "logging.h"

/**
 * WiFi setting keys used to identify settings stored in luna-prefs database.
 * THE SEQUENCE MUST MATCH THE VALUES OF WIFI SETTINGS DEFINED IN wifi_setting.h
 */
static const char* SettingKey[] =
{
    "Null-DO-NOT-USE", /**< Marker used to indicate the start of setting keys */

    "profileList", /**< Setting key for profile list */

    "Last-DO-NOT-USE" /**< Marker used to indicate the end of setting keys */
};

/**
 * @brief Encrypt the given input using the supplied key
 * The encrypt /decrypt functions are useful for storing wifi profiles
 * which may contain secret passwords / passphrases
 */

static char* wifi_setting_encrypt(const char *input_str, const char *key)
{
	BF_KEY *pBfKey = g_new0(BF_KEY, 1);
	gchar *b64str = NULL;
	char *result = NULL;
	long len;
	char *output_str = NULL;
	unsigned char ivec[8] = {0};
	int num = 0;

	if (pBfKey == NULL)
	{
		WCA_LOG_FATAL("Out of memory!");
		goto Exit;
	}

	if (!input_str || !key || !strlen(input_str) || !strlen(key) )
	{
		goto Exit;
	}

	BF_set_key(pBfKey, strlen(key), (const unsigned char*)(key) );

	len = strlen(input_str);

	output_str = g_new0(char, len + 1);
	if (!output_str)
	{
		WCA_LOG_FATAL("Out of memory!");
		goto Exit;
	}

	memset(output_str, 0, len + 1);

	BF_cfb64_encrypt((const unsigned char*)(input_str), (unsigned char*)(output_str),
		     len, pBfKey, ivec, &num, BF_ENCRYPT);

	b64str = g_base64_encode((const guchar*)(output_str), len);
	if (b64str)
	{
		result = strdup(b64str);
		g_free(b64str);
	}

Exit:
	g_free(output_str);
	g_free(pBfKey);
	return result;
}

/**
 * @brief Decrypt the given input using the supplied key
 * The encrypt /decrypt functions are useful for storing wifi profiles
 * which may contain secret passwords / passphrases
 */


static char* wifi_setting_decrypt(const char *input_str, const char *key)
{
	BF_KEY *pBfKey = g_new0(BF_KEY, 1);
	char *result = NULL;
	long len = 0;
	guchar *b64str = NULL;
	char *output_str = NULL;
	unsigned char ivec[8] = {0};
	int num = 0;

	if (pBfKey == NULL)
	{
		WCA_LOG_FATAL("Out of memory!");
		goto Exit;
	}

	if (!input_str || !key || !strlen(input_str) || !strlen(key) )
	{
		goto Exit;
	}

	BF_set_key(pBfKey, strlen(key), (const unsigned char*)key);


	b64str = g_base64_decode((const gchar*)(input_str), (gsize*)(&len) );
	if (b64str)
	{
		output_str = g_new0(char, len + 1);
		if (!output_str)
		{
			WCA_LOG_FATAL("Out of memory!");
			goto Exit;
		}

		memset(output_str, 0, len + 1);

		BF_cfb64_encrypt((const unsigned char*)(b64str), (unsigned char*)(output_str),
			 len, pBfKey, ivec, &num, BF_DECRYPT);

		result = strdup(output_str);

		g_free(output_str);
		g_free(b64str);
	}

Exit:
	g_free(pBfKey);
	return result;
}


static gboolean populate_wifi_profile(jvalue_ref profileObj)
{
	gboolean ret = FALSE;
	jvalue_ref wifiProfileObj, ssidObj, securityListObj, hiddenObj;

	if(jobject_get_exists(profileObj, J_CSTR_TO_BUF("wifiProfile"), &wifiProfileObj))
	{
		raw_buffer enc_profile_buf = jstring_get(wifiProfileObj);
		gchar *enc_profile = g_strdup(enc_profile_buf.m_str);
		gchar *dec_profile = wifi_setting_decrypt(enc_profile, WIFI_LUNA_PREFS_ID);

		jvalue_ref parsedObj = {0};
		jschema_ref input_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
		if(!input_schema)
			goto Exit;

		JSchemaInfo schemaInfo;
		jschema_info_init(&schemaInfo, input_schema, NULL, NULL);
		parsedObj = jdom_parse(j_cstr_to_buffer(dec_profile), DOMOPT_NOOPT, &schemaInfo);
		jschema_release(&input_schema);

		if (jis_null(parsedObj))
		{
			goto Exit;
		}

		gchar *ssid = NULL;
		GStrv security = NULL;
		gboolean hidden = FALSE;
		if(jobject_get_exists(parsedObj,J_CSTR_TO_BUF("ssid"), &ssidObj))
		{
			raw_buffer ssid_buf = jstring_get(ssidObj);
			ssid = g_strdup(ssid_buf.m_str);
			ret = TRUE;
		}
		else
			WCA_LOG_DEBUG("ssid object not found");

		if(NULL == get_profile_by_ssid(ssid))
		{
			if(jobject_get_exists(parsedObj,J_CSTR_TO_BUF("security"), &securityListObj))
			{
				ssize_t i, num_elems = jarray_size(securityListObj);
				security = g_new0(GStrv, 1);
				for(i = 0; i < num_elems; i++)
				{
					jvalue_ref securityObj = jarray_get(securityListObj, i);
					raw_buffer security_buf = jstring_get(securityObj);
					security[i] = g_strdup(security_buf.m_str);
				}
			}
			if(jobject_get_exists(parsedObj,J_CSTR_TO_BUF("wasCreatedWithJoinOther"), &hiddenObj))
			{
				jboolean_get(hiddenObj, &hidden);
			}

			create_new_profile(ssid, security, hidden);
			g_strfreev(security);
		}

		g_free(ssid);
Exit:
		j_release(&parsedObj);
		g_free(dec_profile);
		g_free(enc_profile);
	}

	return ret;
}

/**
 * @brief Get the values of given settings from luna-prefs
 *
 * The param data can be supplied for copying the values of settings
 * (Not required for WIFI_PROFILELIST_SETTING since this function
 * will update the wifi profile list itself
 */

gboolean load_wifi_setting(wifi_setting_type_t setting, void *data)
{
	LPErr lpErr = LP_ERR_NONE;
	LPAppHandle handle;
	char *setting_value = NULL;
	gboolean ret = FALSE;

	lpErr = LPAppGetHandle(WIFI_LUNA_PREFS_ID, &handle);
        if (lpErr)
        {
		WCA_LOG_ERROR("Error in getting LPAppHandle for %s",WIFI_LUNA_PREFS_ID);
		goto Exit;
	}

	lpErr = LPAppCopyValue(handle, SettingKey[setting], &setting_value);
	(void) LPAppFreeHandle(handle, false);

	if (lpErr)
        {
		WCA_LOG_ERROR("Error in executing LPAppCopyValue for %s",SettingKey[setting]);
		goto Exit;
	}


	switch(setting)
	{
		case WIFI_PROFILELIST_SETTING:
		{
			gboolean ret = FALSE;
			jvalue_ref parsedObj = {0};
			jschema_ref input_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
			if(!input_schema)
				goto Exit;

			JSchemaInfo schemaInfo;
			jschema_info_init(&schemaInfo, input_schema, NULL, NULL);
			parsedObj = jdom_parse(j_cstr_to_buffer(setting_value), DOMOPT_NOOPT, &schemaInfo);
			jschema_release(&input_schema);

			if (jis_null(parsedObj)) {
				goto Exit;
			}

			jvalue_ref profileListObj = {0};
			if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileList"), &profileListObj))
			{
				if(!jis_array(profileListObj))
				{
					goto Exit_Case;
				}
				ssize_t i, num_elems = jarray_size(profileListObj);
				for(i = 0; i < num_elems; i++)
				{
					jvalue_ref profileObj = jarray_get(profileListObj, i);
					// Parse json strings to create profiles and append them to profile list
					if(populate_wifi_profile(profileObj) == FALSE)
						goto Exit_Case;
				}
				ret = TRUE;
			}

Exit_Case:
			j_release(&parsedObj);
		}
		default:
			break;
	}
Exit:
	g_free(setting_value);
	return ret;
}

static void add_wifi_profile(jvalue_ref *profile_j, wifi_profile_t *profile)
{
        jobject_put(*profile_j, J_CSTR_TO_JVAL("ssid"), jstring_create(profile->ssid));
        jobject_put(*profile_j, J_CSTR_TO_JVAL("profileId"), jnumber_create_i32(profile->profile_id));
	if(profile->hidden)
		jobject_put(*profile_j, J_CSTR_TO_JVAL("wasCreatedWithJoinOther"), jboolean_create(profile->hidden));

	if(profile->security != NULL)
	{
		jvalue_ref security_list = jarray_create(NULL);
		gsize i;
		for (i = 0; i < g_strv_length(profile->security); i++)
		{
			jarray_append(security_list, jstring_create(profile->security[i]));
		}
		jobject_put(*profile_j, J_CSTR_TO_JVAL("security"), security_list);
	}
}

static gchar *add_wifi_profile_list(void)
{
        if(profile_list_is_empty())
                return NULL;

	gchar *profile_list_str = NULL;
	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(response_schema)
	{
		jvalue_ref profilelist_j = jobject_create();
		jvalue_ref profilelist_arr_j = jarray_create(NULL);

		wifi_profile_t *profile = get_next_profile(NULL);
		while(NULL != profile)
		{
			jvalue_ref profileinfo_j = jobject_create();
			jvalue_ref profile_j = jobject_create();
			add_wifi_profile(&profile_j, profile);
			gchar *profile_str = jvalue_tostring(profile_j, response_schema);
			gchar *enc_profile_str = wifi_setting_encrypt(profile_str, WIFI_LUNA_PREFS_ID);
			jobject_put(profileinfo_j, J_CSTR_TO_JVAL("wifiProfile"), jstring_create(enc_profile_str));
			jarray_append(profilelist_arr_j, profileinfo_j);
			profile = get_next_profile(profile);
			g_free(enc_profile_str);
		}
		jobject_put(profilelist_j, J_CSTR_TO_JVAL("profileList"), profilelist_arr_j);
		profile_list_str = g_strdup(jvalue_tostring(profilelist_j, response_schema));
		jschema_release(&response_schema);
		j_release(&profilelist_j);
	}
	return profile_list_str;
}

/**
 * @brief Set the values of given settings in luna-prefs
 *
 * The param data can be supplied for providing the values of settings
 * (Not required for WIFI_PROFILELIST_SETTING since this function
 * will fetch from wifi profile list itself
 */

gboolean store_wifi_setting(wifi_setting_type_t setting, void *data)
{
	LPErr lpErr = LP_ERR_NONE;
	LPAppHandle handle;
	gboolean ret = FALSE;

	lpErr = LPAppGetHandle(WIFI_LUNA_PREFS_ID, &handle);
        if (lpErr)
        {
		WCA_LOG_ERROR("Error in getting LPAppHandle for %s",WIFI_LUNA_PREFS_ID);
		return FALSE;
	}

	switch(setting)
	{
		case WIFI_PROFILELIST_SETTING:
			{
				/* Convert list of profiles to json string for storing */
				char *profile_list_str = add_wifi_profile_list();
				if(NULL == profile_list_str)
				{
					WCA_LOG_DEBUG("No wifi profiles found");
					goto Exit;
				}
				lpErr = LPAppSetValue(handle, SettingKey[setting], profile_list_str);
				g_free(profile_list_str);
				if (lpErr)
				{
					WCA_LOG_ERROR("Error in executing LPAppSetValue for %s",SettingKey[setting]);
					goto Exit;
				}
				ret = TRUE;
				break;
			}
		default:
			break;
	}
Exit:
	(void) LPAppFreeHandle(handle, true);
	return ret;
}
