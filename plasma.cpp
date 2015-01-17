//
// based on http://www.vankuik.nl/2012-02-09_Writing_ethernet_packets_on_OS_X_and_BSD
//

#include <stdio.h>
#include <math.h>
#include <unistd.h> // usleep
#include "ledpanel.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Syntax: ./test1 [interface]");
        return 1;
    }

    char *interface = argv[1];

    unsigned char src[] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    unsigned char dest[]  = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    rawsocket_connect(interface, (unsigned char *)&src, (unsigned char *)&dest);

    ledpanel_handshake();
    float ph = 0;

    while(true) {
        for(int line = 0; line<64; line++) {
            #define scanlinedata_len 192
            unsigned char scanlinedata[scanlinedata_len];
            int o = 1;
            for(int j=0; j<64; j++) {
                float rr = sin((float)j / 19.1 + ph / 3.6) * cos((float)line / 9.1 + ph / 6.5);
                float gg = cos((float)line / 11.5 - sin(ph / 5.4)) * cos((float)j / 19.3 + ph / 6.3);
                float bb = sin((float)j / 17.3 + line / 13.1 - ph / 9.3) * gg;
                scanlinedata[j * 3 + 0] = fmax(0, fmin(255, (int)(12.0f + 64.0f * rr)));
                scanlinedata[j * 3 + 1] = fmax(0, fmin(255, (int)(12.0f + 64.0f * gg)));
                scanlinedata[j * 3 + 2] = fmax(0, fmin(255, (int)(12.0f + 64.0f * bb)));
            }
            ledpanel_scanline(line, (unsigned char *)&scanlinedata, scanlinedata_len);
        }
        ledpanel_blit();
        usleep(16000); // 16ms delay
        ph += 0.6f;
    }

    rawsocket_disconnect();

    return 0;
};
