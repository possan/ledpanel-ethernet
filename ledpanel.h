#ifndef _LEDPANEL_H_
#define _LEDPANEL_H_

#ifdef __cplusplus
extern "C" {
#endif

extern int rawsocket_connect(char *interface, unsigned char *src_mac, unsigned char *dest_mac);
extern void rawsocket_send(unsigned char *databuf, size_t datalen, unsigned short protocol_type);
extern void rawsocket_disconnect();

extern void ledpanel_handshake();
extern void ledpanel_scanline(int line, unsigned char *scanlinedata, int width);
extern void ledpanel_blit();

#ifdef __cplusplus
}
#endif

#endif