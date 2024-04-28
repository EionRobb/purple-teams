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
 
#define PIDGIN_MARKDOWN

#include "teams_cards.h"
#include "markdown.h"

// See https://learn.microsoft.com/en-us/outlook/actionable-messages/message-card-reference
static gchar *
teams_convert_office365_card_to_html(JsonObject *content)
{
    GString *html = g_string_new("<html><body>");
    const gchar *title = json_object_get_string_member(content, "title");
    const gchar *text = json_object_get_string_member(content, "text");
    JsonArray *sections = json_object_get_array_member(content, "sections");

    if (title) {
        gchar *escaped = markdown_convert_markdown(title, FALSE, FALSE);
        g_string_append_printf(html, "<h1>%s</h1>", title);
        g_free(escaped);
    }
    if (text) {
        gchar *escaped = markdown_convert_markdown(text, FALSE, FALSE);
        g_string_append_printf(html, "<p>%s</p>", escaped);
        g_free(escaped);
    }

    guint i, len = json_array_get_length(sections);
    for(i = 0; i < len; i++) {
        JsonObject *section = json_array_get_object_element(sections, i);
        const gchar *activityTitle = json_object_get_string_member(section, "activityTitle");
        const gchar *activitySubtitle = json_object_get_string_member(section, "activitySubtitle");
        //const gchar *activityImage = json_object_get_string_member(section, "activityImage");
        const gchar *activityText = json_object_get_string_member(section, "activityText");
        const gchar *section_title = json_object_get_string_member(section, "title");
        const gchar *section_text = json_object_get_string_member(section, "text");
        JsonArray *facts = json_object_get_array_member(section, "facts");
        gboolean markdown = !json_object_has_member(section, "markdown") || json_object_get_boolean_member(section, "markdown");
        guint j, len2 = json_array_get_length(facts);

        if (i > 0) {
            g_string_append(html, "<hr />");
        }

#define MARKDOWN(field) markdown ? markdown_convert_markdown((field), FALSE, FALSE) : g_strdup((field))

        if (section_title) {
            gchar *escaped = MARKDOWN(section_title);
            g_string_append_printf(html, "<h2>%s</h2>", escaped);
            g_free(escaped);
        }
        if (activityTitle) {
            gchar *escaped = MARKDOWN(activityTitle);
            g_string_append_printf(html, "<p>%s</p>", escaped);
            g_free(escaped);
        }
        if (activitySubtitle) {
            gchar *escaped = MARKDOWN(activitySubtitle);
            g_string_append_printf(html, "<p>%s</p>", escaped);
            g_free(escaped);
        }
        //if (activityImage) {
        //    g_string_append_printf(html, "<img src=\"%s\" />", activityImage);
        //}
        if (activityText) {
            gchar *escaped = MARKDOWN(activityText);
            g_string_append_printf(html, "<p>%s</p>", escaped);
            g_free(escaped);
        }

        for(j = 0; j < len2; j++) {
            JsonObject *fact = json_array_get_object_element(facts, j);
            const gchar *name = json_object_get_string_member(fact, "name");
            const gchar *value = json_object_get_string_member(fact, "value");

            if (name && value) {
                gchar *escaped_name = MARKDOWN(name);
                gchar *escaped_value = MARKDOWN(value);
                g_string_append_printf(html, "<p><b>%s:</b> %s</p>", escaped_name, escaped_value);
                g_free(escaped_name);
                g_free(escaped_value);
            }
        }

        if (section_text) {
            gchar *escaped = MARKDOWN(section_text);
            g_string_append_printf(html, "<p>%s</p>", escaped);
            g_free(escaped);
        }
#undef MARKDOWN

    }

    JsonArray *potentialAction = json_object_get_array_member(content, "potentialAction");
    len = json_array_get_length(potentialAction);
    for (i = 0; i < len; i++) {
        JsonObject *action = json_array_get_object_element(potentialAction, i);
        const gchar *name = json_object_get_string_member(action, "name");
        JsonArray *targets = json_object_get_array_member(action, "targets");
        guint j, len2 = json_array_get_length(targets);
        const gchar *actionType = json_object_get_string_member(action, "@type");

        if (!purple_strequal(actionType, "OpenUri")) {
            purple_debug_error("teams", "Unhandled action type: %s\n", actionType);
            continue;
        }

        for (j = 0; j < len2; j++) {
            JsonObject *target = json_array_get_object_element(targets, j);
            const gchar *os = json_object_get_string_member(target, "os");
            const gchar *uri = json_object_get_string_member(target, "uri");

            if (os && !purple_strequal(os, "default")) {
                // other options are "android", "ios", "windows"
                continue;
            }

            g_string_append_printf(html, "<a href=\"%s\">%s</a><br />", uri, name);
            break;
        }
    }

    g_string_append(html, "</body></html>");

    return g_string_free(html, FALSE);
}

// See https://learn.microsoft.com/en-us/outlook/actionable-messages/adaptive-card and https://adaptivecards.io/
static gchar *
teams_convert_adaptive_card_to_html(JsonObject *content)
{
    return NULL;
}

gchar *
teams_convert_card_to_html(JsonObject *content, const gchar *content_type)
{
    if (purple_strequal(content_type, "application/vnd.microsoft.teams.card.o365connector")) {
        return teams_convert_office365_card_to_html(content);
    } else if (purple_strequal(content_type, "application/vnd.microsoft.card.adaptive")) {
        return teams_convert_adaptive_card_to_html(content);
    }

    purple_debug_error("teams", "Unknown card type: %s\n", content_type);

    return NULL;
}
