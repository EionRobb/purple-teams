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

#include "libteams.h"

gchar *teams_string_get_chunk(const gchar *haystack, gsize len, const gchar *start, const gchar *end);

gchar *teams_jsonobj_to_string(JsonObject *jsonobj);
gchar *teams_jsonarr_to_string(JsonArray *jsonarr);
JsonObject *json_decode_object(const gchar *data, gssize len);
JsonArray *json_decode_array(const gchar *data, gssize len);

const gchar *teams_contact_url_to_name(const gchar *url);
const gchar *teams_thread_url_to_name(const gchar *url);

gchar *teams_hmac_sha256(gchar *input);

gint64 teams_get_js_time();

PurpleAccount *find_acct(const char *prpl, const char *acct_id);

const gchar *teams_user_url_prefix(const gchar *who);
const gchar *teams_strip_user_prefix(const gchar *who);

PurpleGroup *teams_get_blist_group(TeamsAccount *sa);
gboolean teams_is_user_self(TeamsAccount *sa, const gchar *username);

gchar *teams_gunzip(const guchar *gzip_data, gsize *len_ptr);
