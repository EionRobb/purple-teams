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

void teams_logout(TeamsAccount *sa);
void teams_begin_web_login(TeamsAccount *sa);
void teams_begin_oauth_login(TeamsAccount *sa);
void teams_refresh_token_login(TeamsAccount *sa);
void teams_begin_soapy_login(TeamsAccount *sa);

gboolean teams_oauth_refresh_token(TeamsAccount *sa);
void teams_do_web_auth(TeamsAccount *sa);

#endif /* TEAMS_LOGIN_H */
