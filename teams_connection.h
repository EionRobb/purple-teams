/*
 * Teams Plugin for libpurple/Pidgin
 * Copyright (c) 2014-2020 Eion Robb
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#ifndef TEAMS_CONNECTION_H
#define TEAMS_CONNECTION_H

#include "libteams.h"

typedef void (*TeamsProxyCallbackFunc)(TeamsAccount *sa, JsonNode *node, gpointer user_data);
typedef void (*TeamsProxyCallbackErrorFunc)(TeamsAccount *sa, const gchar *data, gssize data_len, gpointer user_data);

/*
 * This is a bitmask.
 */
typedef enum
{
	TEAMS_METHOD_GET    = 0x0001,
	TEAMS_METHOD_POST   = 0x0002,
	TEAMS_METHOD_PUT    = 0x0004,
	TEAMS_METHOD_DELETE = 0x0008,
	TEAMS_METHOD_SSL    = 0x1000,
} TeamsMethod;

typedef struct _TeamsConnection TeamsConnection;
struct _TeamsConnection {
	TeamsAccount *sa;
	gchar *url;
	TeamsProxyCallbackFunc callback;
	gpointer user_data;
	PurpleHttpConnection *http_conn;
	TeamsProxyCallbackErrorFunc error_callback;
};

TeamsConnection *teams_post_or_get(TeamsAccount *sa, TeamsMethod method,
		const gchar *host, const gchar *url, const gchar *postdata,
		TeamsProxyCallbackFunc callback_func, gpointer user_data,
		gboolean keepalive);

void teams_update_cookies(TeamsAccount *sa, const gchar *headers);		
gchar *teams_cookies_to_string(TeamsAccount *sa);

//TeamsConnection *teams_fetch_url_request();

#endif /* TEAMS_CONNECTION_H */
