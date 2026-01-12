#ifndef _GLIBCOMPAT_H_
#define _GLIBCOMPAT_H_

#include <glib.h>

#if !GLIB_CHECK_VERSION(2, 68, 0)
#define g_memdup2(mem, size) g_memdup((mem), (size))
#endif /* 2.68.0 */

#if !GLIB_CHECK_VERSION(2, 34, 0)
static inline GSList *
g_slist_copy_deep(GSList *list, GCopyFunc copy_func, gpointer user_data)
{
	GSList *new_list = NULL;
	GSList *cur;

	for (cur = list; cur != NULL; cur = cur->next) {
		gpointer new_data = copy_func ? copy_func(cur->data, user_data) : cur->data;
		new_list = g_slist_append(new_list, new_data); //TODO probably inefficient
	}

	return new_list;
}
#endif /* 2.34.0 */

#if !GLIB_CHECK_VERSION(2, 32, 0)
#define g_hash_table_contains(hash_table, key) g_hash_table_lookup_extended((hash_table), (key), NULL, NULL)
#endif /* 2.32.0 */

#if !GLIB_CHECK_VERSION(2, 28, 0)
static inline gint64
g_get_real_time()
{
	GTimeVal val;
	
	g_get_current_time (&val);
	
	return (((gint64) val.tv_sec) * 1000000) + val.tv_usec;
}
#endif /* 2.28.0 */

#endif /*_GLIBCOMPAT_H_*/