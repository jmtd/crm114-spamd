CFLAGS = -Wall
LDFLAGS = -lident

dspam-spamd: dspam-spamd.c

clean:
	rm -f *~ dspam-spamd