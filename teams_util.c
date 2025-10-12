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
 
#include "teams_util.h"

gchar *
teams_string_get_chunk(const gchar *haystack, gsize len, const gchar *start, const gchar *end)
{
	const gchar *chunk_start, *chunk_end;
	g_return_val_if_fail(haystack && start, NULL);
	
	if (len > 0) {
		chunk_start = g_strstr_len(haystack, len, start);
	} else {
		chunk_start = strstr(haystack, start);
	}
	g_return_val_if_fail(chunk_start, NULL);
	chunk_start += strlen(start);
	
	if (end != NULL) {
		if (len > 0) {
			chunk_end = g_strstr_len(chunk_start, len - (chunk_start - haystack), end);
		} else {
			chunk_end = strstr(chunk_start, end);
		}
		g_return_val_if_fail(chunk_end, NULL);
		
		return g_strndup(chunk_start, chunk_end - chunk_start);
	} else {
		return g_strdup(chunk_start);
	}
}

gchar *
teams_jsonobj_to_string(JsonObject *jsonobj)
{
	JsonGenerator *generator;
	JsonNode *root;
	gchar *string;
	
	root = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(root, jsonobj);
	
	generator = json_generator_new();
	json_generator_set_root(generator, root);
	
	string = json_generator_to_data(generator, NULL);
	
	g_object_unref(generator);
	json_node_free(root);
	
	return string;
}

gchar *
teams_jsonarr_to_string(JsonArray *jsonarr)
{
	JsonGenerator *generator;
	JsonNode *root;
	gchar *string;
	
	root = json_node_new(JSON_NODE_ARRAY);
	json_node_set_array(root, jsonarr);
	
	generator = json_generator_new();
	json_generator_set_root(generator, root);
	
	string = json_generator_to_data(generator, NULL);
	
	g_object_unref(generator);
	json_node_free(root);
	
	return string;
}

JsonNode *
json_decode(const gchar *data, gssize len)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root = NULL;
	
	if (!data || !json_parser_load_from_data(parser, data, len, NULL))
	{
		purple_debug_error("teams", "Error parsing JSON: %s\n", data ? data : "(null)");
	} else {
		root = json_parser_get_root(parser);
		if (root != NULL) {
			root = json_node_copy(root);
		}
	}
	g_object_unref(parser);
	
	return root;
}

JsonObject *
json_decode_object(const gchar *data, gssize len)
{
	JsonNode *root = json_decode(data, len);
	JsonObject *ret;
	
	g_return_val_if_fail(root, NULL);
	
	if (!JSON_NODE_HOLDS_OBJECT(root)) {
		// That ain't my thumb, neither!
		json_node_free(root);
		return NULL;
	}
	
	ret = json_node_dup_object(root);

	json_node_free(root);

	return ret;
}

JsonArray *
json_decode_array(const gchar *data, gssize len)
{
	JsonNode *root = json_decode(data, len);
	JsonArray *ret;
	
	g_return_val_if_fail(root, NULL);
	
	if (!JSON_NODE_HOLDS_ARRAY(root)) {
		json_node_free(root);
		return NULL;
	}
	
	ret = json_node_dup_array(root);

	json_node_free(root);

	return ret;
}

/** turn https://bay-client-s.gateway.messenger.live.com/v1/users/ME/contacts/8:eionrobb 
      or https://bay-client-s.gateway.messenger.live.com/v1/users/8:eionrobb/presenceDocs/messagingService 
	into eionrobb
*/
const gchar *
teams_contact_url_to_name(const gchar *url)
{
	static gchar *tempname = NULL;
	const gchar *start, *end;
	
	g_return_val_if_fail(url != NULL, NULL);
	
	// Strip the numeric prefix off these ones
	start = g_strrstr(url, "/8:");
	if (!start) start = g_strrstr(url, "/1:");
	if (!start) start = g_strrstr(url, "/4:");
	if (start) start = start + 2;
	
	// Keep the prefix on these ones
	if (!start) start = g_strrstr(url, "/2:");
	if (!start) start = g_strrstr(url, "/28:");
	if (!start) start = g_strrstr(url, "/48:");
	if (start) start = start + 1;
	if (!start) return NULL;
	
	if ((end = strchr(start, '/'))) {
		g_free(tempname);
		tempname = g_strndup(start, end - start);
		return tempname;
	}
	
	g_free(tempname);
	tempname = g_strdup(start);
	return tempname;
}

/** turn https://bay-client-s.gateway.messenger.live.com/v1/users/ME/conversations/19:blah@thread.skype
	into 19:blah@thread.skype
*/
const gchar *
teams_thread_url_to_name(const gchar *url)
{
	static gchar *tempname = NULL;
	const gchar *start, *end;
	
	start = g_strrstr(url, "/19:");
	if (!start) return NULL;
	start = start + 1;
	
	if ((end = strchr(start, '/'))) {
		g_free(tempname);
		tempname = g_strndup(start, end - start);
		return tempname;
	}
	
	return start;
}

/** Blatantly stolen from MSN prpl, with super-secret SHA256 change! */
#define BUFSIZE	256
char *
teams_hmac_sha256(char *input)
{
	GChecksum *hash;
	const guchar productKey[] = TEAMS_LOCKANDKEY_SECRET;
	const guchar productID[]  = TEAMS_LOCKANDKEY_APPID;
	const char hexChars[]     = "0123456789abcdef";
	char buf[BUFSIZE];
	unsigned char sha256Hash[32];
	gsize sha256HashLen = sizeof(sha256Hash);
	unsigned char *newHash;
	unsigned int *sha256Parts;
	unsigned int *chlStringParts;
	unsigned int newHashParts[5];
	gchar *output;

	long long nHigh = 0, nLow = 0;

	int len;
	int i;
	
	hash = g_checksum_new(G_CHECKSUM_SHA256);
	g_checksum_update(hash, (guchar *)input, strlen(input));
	g_checksum_update(hash, productKey, sizeof(productKey) - 1);
	g_checksum_get_digest(hash, (guchar *)sha256Hash, &sha256HashLen);
	g_checksum_free(hash);
	
	/* Split it into four integers */
	sha256Parts = (unsigned int *)sha256Hash;
	for (i = 0; i < 4; i++) {
		/* adjust endianess */
		sha256Parts[i] = GUINT_TO_LE(sha256Parts[i]);

		/* & each integer with 0x7FFFFFFF          */
		/* and save one unmodified array for later */
		newHashParts[i] = sha256Parts[i];
		sha256Parts[i] &= 0x7FFFFFFF;
	}

	/* make a new string and pad with '0' to length that's a multiple of 8 */
	snprintf(buf, BUFSIZE - 5, "%s%s", input, productID);
	len = strlen(buf);
	if ((len % 8) != 0) {
		int fix = 8 - (len % 8);
		memset(&buf[len], '0', fix);
		buf[len + fix] = '\0';
		len += fix;
	}

	/* split into integers */
	chlStringParts = (unsigned int *)buf;

	/* this is magic */
	for (i = 0; i < (len / 4); i += 2) {
		long long temp;

		chlStringParts[i] = GUINT_TO_LE(chlStringParts[i]);
		chlStringParts[i + 1] = GUINT_TO_LE(chlStringParts[i + 1]);

		temp = (0x0E79A9C1 * (long long)chlStringParts[i]) % 0x7FFFFFFF;
		temp = (sha256Parts[0] * (temp + nLow) + sha256Parts[1]) % 0x7FFFFFFF;
		nHigh += temp;

		temp = ((long long)chlStringParts[i + 1] + temp) % 0x7FFFFFFF;
		nLow = (sha256Parts[2] * temp + sha256Parts[3]) % 0x7FFFFFFF;
		nHigh += nLow;
	}
	nLow = (nLow + sha256Parts[1]) % 0x7FFFFFFF;
	nHigh = (nHigh + sha256Parts[3]) % 0x7FFFFFFF;

	newHashParts[0] ^= nLow;
	newHashParts[1] ^= nHigh;
	newHashParts[2] ^= nLow;
	newHashParts[3] ^= nHigh;

	/* adjust endianness */
	for(i = 0; i < 4; i++)
		newHashParts[i] = GUINT_TO_LE(newHashParts[i]);
	
	/* make a string of the parts */
	newHash = (unsigned char *)newHashParts;
	
	/* convert to hexadecimal */
	output = g_new0(gchar, 33);
	for (i = 0; i < 16; i++)
	{
		output[i * 2] = hexChars[(newHash[i] >> 4) & 0xF];
		output[(i * 2) + 1] = hexChars[newHash[i] & 0xF];
	}
	output[32] = '\0';
	
	return output;
}

gint64
teams_get_js_time()
{
#if GLIB_CHECK_VERSION(2, 28, 0)
	return (g_get_real_time() / 1000);
#else
	GTimeVal val;
	
	g_get_current_time (&val);
	
	return (((gint64) val.tv_sec) * 1000) + (val.tv_usec / 1000);
#endif
}

/* copied from oscar.c to be libpurple 2.1 compatible */
PurpleAccount *
find_acct(const char *prpl, const char *acct_id)
{
	PurpleAccount *acct = NULL;
	
	/* If we have a specific acct, use it */
	if (acct_id && *acct_id) {
		acct = purple_accounts_find(acct_id, prpl);
		if (acct && !purple_account_is_connected(acct))
			acct = NULL;
	} else { /* Otherwise find an active account for the protocol */
		GList *l = purple_accounts_get_all();
		while (l) {
			if (!strcmp(prpl, purple_account_get_protocol_id(l->data))
				&& purple_account_is_connected(l->data)) {
				acct = l->data;
				break;
			}
			l = l->next;
		}
	}
	
	return acct;
}

const gchar *
teams_user_url_prefix(const gchar *who)
{
	if(TEAMS_BUDDY_IS_S4B(who) || TEAMS_BUDDY_IS_BOT(who) || TEAMS_BUDDY_IS_NOTIFICATIONS(who)) {
		return ""; // already has a prefix
	} else if (TEAMS_BUDDY_IS_MSN(who)) {
		return "1:";
	} else if(TEAMS_BUDDY_IS_PHONE(who)) {
		return "4:";
	} else {
		return "8:";
	}
}

const gchar *
teams_strip_user_prefix(const gchar *who)
{
	if (who && who[0] && who[1] == ':') {
		if (who[0] != '2') {
			return who + 2;
		}
	}
	
	return who;
}

PurpleGroup *
teams_get_blist_group(TeamsAccount *sa)
{
	PurpleGroup *group;
	gchar *group_name;
	
	if (purple_account_get_string(sa->account, "group_name", NULL)) {
		group_name = g_strdup(purple_account_get_string(sa->account, "group_name", NULL));
	} else if (!sa->tenant || !*sa->tenant) {
		group_name = g_strdup("Teams");
	} else {
		//TODO nicer name
		group_name = g_strdup_printf("Teams - %s", sa->tenant);
	}
	
	group = purple_blist_find_group(group_name);
	if (!group)
	{
		group = purple_group_new(group_name);
		purple_blist_add_group(group, NULL);
	}
	
	g_free(group_name);
	
	return group;
}

gboolean
teams_is_user_self(TeamsAccount *sa, const gchar *username) {
	if (!username || *username == 0) {
		return FALSE;
	}
	
	if (sa->username) {
		if (g_str_equal(username, sa->username)) {
			return TRUE;
		}
	}
	
	if (sa->primary_member_name) {
		if (g_str_equal(username, sa->primary_member_name)) {
			return TRUE;
		}
	}
	
	return !g_ascii_strcasecmp(username, purple_account_get_username(sa->account));
}

#include <zlib.h>

gchar *
teams_gunzip(const guchar *gzip_data, gsize *len_ptr)
{
	gsize gzip_data_len	= *len_ptr;
	z_stream zstr;
	int gzip_err = 0;
	gchar *data_buffer;
	gulong gzip_len = G_MAXUINT16;
	GString *output_string = NULL;

	data_buffer = g_new0(gchar, gzip_len);

	zstr.next_in = NULL;
	zstr.avail_in = 0;
	zstr.zalloc = Z_NULL;
	zstr.zfree = Z_NULL;
	zstr.opaque = 0;
	gzip_err = inflateInit2(&zstr, MAX_WBITS+32);
	if (gzip_err != Z_OK)
	{
		g_free(data_buffer);
		purple_debug_error("teams", "no built-in gzip support in zlib\n");
		return NULL;
	}
	
	zstr.next_in = (Bytef *)gzip_data;
	zstr.avail_in = gzip_data_len;
	
	zstr.next_out = (Bytef *)data_buffer;
	zstr.avail_out = gzip_len;
	
	gzip_err = inflate(&zstr, Z_SYNC_FLUSH);

	if (gzip_err == Z_DATA_ERROR)
	{
		inflateEnd(&zstr);
		gzip_err = inflateInit2(&zstr, -MAX_WBITS);
		if (gzip_err != Z_OK)
		{
			g_free(data_buffer);
			purple_debug_error("teams", "Cannot decode gzip header\n");
			return NULL;
		}
		zstr.next_in = (Bytef *)gzip_data;
		zstr.avail_in = gzip_data_len;
		zstr.next_out = (Bytef *)data_buffer;
		zstr.avail_out = gzip_len;
		gzip_err = inflate(&zstr, Z_SYNC_FLUSH);
	}
	output_string = g_string_new("");
	while (gzip_err == Z_OK)
	{
		//append data to buffer
		output_string = g_string_append_len(output_string, data_buffer, gzip_len - zstr.avail_out);
		//reset buffer pointer
		zstr.next_out = (Bytef *)data_buffer;
		zstr.avail_out = gzip_len;
		gzip_err = inflate(&zstr, Z_SYNC_FLUSH);
	}
	if (gzip_err == Z_STREAM_END)
	{
		output_string = g_string_append_len(output_string, data_buffer, gzip_len - zstr.avail_out);
	} else {
		purple_debug_error("teams", "gzip inflate error\n");
	}
	inflateEnd(&zstr);

	g_free(data_buffer);	

	*len_ptr = output_string->len;
	return g_string_free(output_string, FALSE);
}
