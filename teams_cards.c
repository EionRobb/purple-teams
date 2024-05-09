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

GString *
teams_adaptive_card_item_to_html(GString *html, JsonObject *item)
{
    const gchar *type = json_object_get_string_member(item, "type");

    if (purple_strequal(type, "TextBlock")) {
        const gchar *text = json_object_get_string_member(item, "text");
        const gchar *size = json_object_get_string_member(item, "size");
        const gchar *weight = json_object_get_string_member(item, "weight");
        const gchar *color = json_object_get_string_member(item, "color");
        const gchar *wrap = json_object_get_string_member(item, "wrap");
        const gchar *fontType = json_object_get_string_member(item, "fontType");
        const gchar *separator = json_object_get_string_member(item, "separator");

        if (separator) {
            g_string_append(html, "<hr />");
        }
        if (text) {
            gchar *escaped = markdown_convert_markdown(text, TRUE, FALSE);
            GString *style = g_string_new("");
            if (size) {
                g_string_append_printf(style, "font-size: %s;", size);
            }
            if (weight) {
                g_string_append_printf(style, "font-weight: %s;", weight);
            }
            if (color) {
                if (purple_strequal(color, "attention")) {
                    color = "red";
                } else if (purple_strequal(color, "good")) {
                    color = "green";
                } else if (purple_strequal(color, "warning")) {
                    color = "orange";
                } else if (purple_strequal(color, "accent")) {
                    color = "blue";
                } else if (purple_strequal(color, "dark")) {
                    color = "black";
                } else if (purple_strequal(color, "light")) {
                    color = "grey";
                }
                g_string_append_printf(style, "color: %s;", color);
            }
            if (fontType) {
                g_string_append_printf(style, "font-family: %s;", fontType);
            }
            if (wrap) {
                g_string_append_printf(style, "white-space: %s;", purple_strequal(wrap, "true") ? "normal" : "nowrap");
            }

            g_string_append_printf(html, "<span style=\"%s\">%s</span>", style->str, escaped);
            g_string_free(style, TRUE);
            g_free(escaped);
        }
    } else if (purple_strequal(type, "RichTextBlock")) {
        JsonArray *inlines = json_object_get_array_member(item, "inlines");
        guint j, len2 = json_array_get_length(inlines);

        for (j = 0; j < len2; j++) {
            JsonObject *inline_element = json_array_get_object_element(inlines, j);
            const gchar *inline_type = json_object_get_string_member(inline_element, "type");
            const gchar *text = json_object_get_string_member(inline_element, "text");

            if (purple_strequal(inline_type, "TextRun") && text) {
                gboolean italic = json_object_get_boolean_member(inline_element, "italic");
                const gchar *weight = json_object_get_string_member(inline_element, "weight");
                const gchar *fontType = json_object_get_string_member(inline_element, "fontType");
                const gchar *color = json_object_get_string_member(inline_element, "color");

                GString *style = g_string_new("");
                if (italic) {
                    g_string_append(style, "font-style: italic;");
                }
                if (weight) {
                    g_string_append_printf(style, "font-weight: %s;", weight);
                }
                if (fontType) {
                    g_string_append_printf(style, "font-family: %s;", fontType);
                }
                if (color) {
                    if (purple_strequal(color, "attention")) {
                        color = "red";
                    } else if (purple_strequal(color, "good")) {
                        color = "green";
                    } else if (purple_strequal(color, "warning")) {
                        color = "orange";
                    } else if (purple_strequal(color, "accent")) {
                        color = "blue";
                    } else if (purple_strequal(color, "dark")) {
                        color = "black";
                    } else if (purple_strequal(color, "light")) {
                        color = "grey";
                    }
                    g_string_append_printf(style, "color: %s;", color);
                }

                gchar *escaped = markdown_convert_markdown(text, TRUE, FALSE);
                g_string_append_printf(html, "<span style=\"%s\">%s</p>", style->str, escaped);
                g_free(escaped);
                g_string_free(style, TRUE);
            } else {
                purple_debug_error("teams", "Unhandled adaptive card inline type: %s\n", inline_type);
            }
        }
    } else if (purple_strequal(type, "Image")) {
        const gchar *url = json_object_get_string_member(item, "url");
        //const gchar *size = json_object_get_string_member(item, "size");

        if (url) {
            //GString *style = g_string_new("");
            //if (size) {
            //    g_string_append_printf(style, "width: %s;", size);
            //}

            //g_string_append_printf(html, "<img src=\"%s\" style=\"%s\" />", url, style->str);
            g_string_append_printf(html, "Image: %s<br/>", url);
            //g_string_free(style, TRUE);
        }
    } else if (purple_strequal(type, "Media")) {
        const gchar *poster = json_object_get_string_member(item, "poster");
        JsonArray *sources = json_object_get_array_member(item, "sources");
        guint j, len2 = json_array_get_length(sources);

        if (poster) {
            //g_string_append_printf(html, "<img src=\"%s\" />", poster);
            g_string_append_printf(html, "Poster: %s<br/>", poster);
        }

        for (j = 0; j < len2; j++) {
            JsonObject *source = json_array_get_object_element(sources, j);
            const gchar *url = json_object_get_string_member(source, "url");
            const gchar *mimeType = json_object_get_string_member(source, "mimeType");

            if (url) {
                //g_string_append_printf(html, "<video controls><source src=\"%s\" type=\"%s\" /></video>", url, mimeType);
                g_string_append_printf(html, "Video: %s (%s)<br/>", url, mimeType);
            }
        }
    } else if (purple_strequal(type, "ActionSet")) {
        JsonArray *actions = json_object_get_array_member(item, "actions");
        guint j, len2 = json_array_get_length(actions);

        for (j = 0; j < len2; j++) {
            JsonObject *action = json_array_get_object_element(actions, j);
            const gchar *actionType = json_object_get_string_member(action, "type");
            const gchar *title = json_object_get_string_member(action, "title");
            const gchar *url = json_object_get_string_member(action, "url");

            if (purple_strequal(actionType, "Action.OpenUrl")) {
                g_string_append_printf(html, "<a href=\"%s\">%s</a><br />", url, title);
            } else {
                purple_debug_error("teams", "Unhandled action type: %s\n", actionType);
            }
        }
    } else if (purple_strequal(type, "ColumnSet")) {
        JsonArray *columns = json_object_get_array_member(item, "columns");
        guint j, len2 = json_array_get_length(columns);

        for (j = 0; j < len2; j++) {
            JsonObject *column = json_array_get_object_element(columns, j);
            const gchar *columnType = json_object_get_string_member(column, "type");

            if (purple_strequal(columnType, "Column")) {
                JsonArray *items = json_object_get_array_member(column, "items");
                guint k, len3 = json_array_get_length(items);

                for (k = 0; k < len3; k++) {
                    JsonObject *column_item = json_array_get_object_element(items, k);
                    teams_adaptive_card_item_to_html(html, column_item);
                }
            } else {
                purple_debug_error("teams", "Unhandled adaptive card column type: %s\n", columnType);
            }
        }
    } else {
        purple_debug_error("teams", "Unhandled adaptive card element type: %s\n", type);
    }

    return html;
}

// See https://learn.microsoft.com/en-us/outlook/actionable-messages/adaptive-card and https://adaptivecards.io/
static gchar *
teams_convert_adaptive_card_to_html(JsonObject *content)
{
    GString *html = g_string_new("<html><body>");
    JsonArray *body = json_object_get_array_member(content, "body");
    guint i, len = json_array_get_length(body);

    for (i = 0; i < len; i++) {
        JsonObject *element = json_array_get_object_element(body, i);
        
        teams_adaptive_card_item_to_html(html, element);
        g_string_append(html, "<br />");
    }

    g_string_append(html, "</body></html>");

    return g_string_free(html, FALSE);
}

// See https://github.com/microsoft/botframework-sdk/blob/main/specs/botframework-activity/botframework-cards.md#media-card-media or https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-add-media-attachments?view=azure-bot-service-4.0#add-an-audiocard-attachment
static gchar *
teams_convert_media_card_to_html(JsonObject *content)
{
    //{"duration":"PT2S","media":[{"url":"https://au-prod.asyncgw.teams.microsoft.com/v1/objects/0-eau-d1-093f952d123456788141efe4c1346b6a/views/audio"}]}
    //const gchar *duration = json_object_get_string_member(content, "duration");  //ISO8601 duration
    JsonArray *media = json_object_get_array_member(content, "media");
    guint i, len = json_array_get_length(media);
    GString *html = g_string_new("<html><body>");
 
    g_string_append_printf(html, "<b>%s:</b>", _("Media"));
    for (i = 0; i < len; i++) {
        JsonObject *media_item = json_array_get_object_element(media, i);
        const gchar *url = json_object_get_string_member(media_item, "url");

        if (url) {
            if (i > 0) {
                g_string_append(html, "<br>");
            }
            g_string_append(html, url);
        }
    }

    g_string_append(html, "</body></html>");

    return g_string_free(html, FALSE);
}

// See https://learn.microsoft.com/en-us/outlook/actionable-messages/message-card-reference#hero-card and https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-add-rich-cards?view=azure-bot-service-4.0#add-a-hero-card-to-a-message
static gchar *
teams_convert_hero_card_to_html(JsonObject *content)
{
    GString *html = g_string_new("<html><body>");
    const gchar *title = json_object_get_string_member(content, "title");
    const gchar *subtitle = json_object_get_string_member(content, "subtitle");
    const gchar *text = json_object_get_string_member(content, "text");
    JsonObject *tap = json_object_get_object_member(content, "tap");
    JsonArray *images = json_object_get_array_member(content, "images");
    JsonArray *buttons = json_object_get_array_member(content, "buttons");
    guint i, len;

    if (tap) {
        const gchar *tap_type = json_object_get_string_member(tap, "type");
        const gchar *tap_value = json_object_get_string_member(tap, "value");

        if (purple_strequal(tap_type, "openUrl")) {
            g_string_append_printf(html, "<a href=\"%s\">", tap_value);
        } else {
            purple_debug_error("teams", "Unhandled tap type: %s\n", tap_type);
        }
    }
    if (title) {
        gchar *escaped = markdown_convert_markdown(title, FALSE, FALSE);
        g_string_append_printf(html, "<h1>%s</h1>", escaped);
        g_free(escaped);
    }
    if (subtitle) {
        gchar *escaped = markdown_convert_markdown(subtitle, FALSE, FALSE);
        g_string_append_printf(html, "<h2>%s</h2>", escaped);
        g_free(escaped);
    }
    if (text) {
        gchar *escaped = markdown_convert_markdown(text, FALSE, FALSE);
        g_string_append_printf(html, "<p>%s</p>", escaped);
        g_free(escaped);
    }
    len = json_array_get_length(images);
    for (i = 0; i < len; i++) {
        JsonObject *image = json_array_get_object_element(images, i);
        const gchar *url = json_object_get_string_member(image, "url");
        const gchar *alt = json_object_get_string_member(image, "alt");
        JsonObject *image_tap = json_object_get_object_member(image, "tap");
        const gchar *image_tap_type = json_object_get_string_member(image_tap, "type");

        if (url) {
            if (image_tap && purple_strequal(image_tap_type, "openUrl")) {
                const gchar *image_tap_value = json_object_get_string_member(image_tap, "value");

                //g_string_append_printf(html, "<a href=\"%s\"><img src=\"%s\" alt=\"%s\" /></a>", image_tap_value, url, alt);
                g_string_append_printf(html, "<a href=\"%s\">Image: %s (%s) %s</a><br/>", image_tap_value, url, alt, image_tap_value);
            } else {
                //g_string_append_printf(html, "<img src=\"%s\" alt=\"%s\" />", url, alt);
                g_string_append_printf(html, "Image: %s (%s)<br/>", url, alt);
            }
        }
    }

    len = json_array_get_length(buttons);
    for (i = 0; i < len; i++) {
        JsonObject *button = json_array_get_object_element(buttons, i);
        const gchar *type = json_object_get_string_member(button, "type");
        const gchar *title = json_object_get_string_member(button, "title");
        const gchar *value = json_object_get_string_member(button, "value");

        if (purple_strequal(type, "openUrl")) {
            g_string_append_printf(html, "<a href=\"%s\">%s</a><br />", value, title);
        } else {
            purple_debug_error("teams", "Unhandled button type: %s\n", type);
        }
    }

    if (tap) {
        g_string_append(html, "</a>");
    }
    g_string_append(html, "</body></html>");

    return g_string_free(html, FALSE);
}

gchar *
teams_convert_card_to_html(JsonObject *content, const gchar *content_type)
{
    if (purple_strequal(content_type, "application/vnd.microsoft.teams.card.o365connector")) {
        return teams_convert_office365_card_to_html(content);
    } else if (purple_strequal(content_type, "application/vnd.microsoft.card.adaptive")) {
        return teams_convert_adaptive_card_to_html(content);
    } else if (purple_strequal(content_type, "application/vnd.microsoft.card.audio") || 
                purple_strequal(content_type, "application/vnd.microsoft.card.video") || 
                purple_strequal(content_type, "application/vnd.microsoft.card.animation")) {
        return teams_convert_media_card_to_html(content);
    } else if (purple_strequal(content_type, "application/vnd.microsoft.card.hero") ||
                purple_strequal(content_type, "application/vnd.microsoft.card.thumbnail")) {
        // It's the same, but thumbnail has an array of images, but a hero only one
        return teams_convert_hero_card_to_html(content);
    //} else if (purple_strequal(content_type, "application/vnd.microsoft.com.card.receipt")) {
    //    return teams_convert_receipt_card_to_html(content);
    //} else if (purple_strequal(content_type, "application/vnd.microsoft.com.card.signin")) {
    //    return teams_convert_signin_card_to_html(content);
    }

    purple_debug_error("teams", "Unknown card type: %s\n", content_type);

    return NULL;
}
