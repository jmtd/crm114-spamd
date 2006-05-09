#include <glib.h>

GMainLoop *mainloop;

gboolean
input_event (GIOChannel *in, GIOCondition condition, gpointer data)
{
	GIOChannel *out = (GIOChannel*) data;
	gchar *input;
	gsize length;
	gsize written;

	if (!(condition & G_IO_IN))
	{
		g_main_loop_quit(mainloop);
		return FALSE;
	}
	if (g_io_channel_read_line(in, &input, &length, NULL, NULL) != G_IO_STATUS_NORMAL)
	{
		g_main_loop_quit(mainloop);
		return FALSE;
	}
	if (g_io_channel_write_chars(out, input, length, &written, NULL) != G_IO_STATUS_NORMAL)
	{
		g_main_loop_quit(mainloop);
		return FALSE;
	}
	g_free(input);
	g_io_channel_flush(out, NULL);
	
	return TRUE;
}

int
main()
{
	GIOChannel *in;
	GIOChannel *out;
	
	in = g_io_channel_unix_new(0);
	out = g_io_channel_unix_new(1);
	g_io_channel_set_encoding(in, NULL, NULL);
	g_io_channel_set_encoding(out, NULL, NULL);
	
	g_io_add_watch(in, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL, input_event, (gpointer)out);
	mainloop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(mainloop);
	return 0;
}
