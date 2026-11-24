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
 
#ifndef TEAMS_LOGIN_H
#define TEAMS_LOGIN_H

#include "libteams.h"
#include "teams_connection.h"

#include <util.h>

#define TEAMS_PERSONAL_TENANT_ID "9188040d-6c67-4c5b-b112-36a304b66dad"

void teams_logout(TeamsAccount *sa);

gboolean teams_oauth_refresh_token(TeamsAccount *sa);
void teams_do_web_auth(TeamsAccount *sa);
void teams_do_devicecode_login(TeamsAccount *sa);

/* Personal/TFL: read the persisted OAuth refresh_token (stored as the account
 * password) for this account. Returns a newly-allocated string or NULL. */
gchar *teams_load_refresh_token_password(PurpleAccount *account);

/* Personal/TFL: headless OAuth auth-code login. Feed the redirect URL (or bare
 * code) captured by an external browser; exchanges it for tokens and persists the
 * refresh_token for silent future logins. */
void teams_do_authcode_login(TeamsAccount *sa, const gchar *code_or_url);

#endif /* TEAMS_LOGIN_H */
