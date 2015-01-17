//
// based on http://www.vankuik.nl/2012-02-09_Writing_ethernet_packets_on_OS_X_and_BSD
//

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/bpf.h>
#include <unistd.h>
#include "ledpanel.h"

unsigned char g_src_mac[ETHER_ADDR_LEN] = { 0, };
unsigned char g_dest_mac[ETHER_ADDR_LEN] = { 0, } ;
int g_bpf;
unsigned char *ledpanel_tempbuffer;

struct frame_t {
    struct ether_header header;
    unsigned char payload[ETHER_MAX_LEN - ETHER_HDR_LEN];
    ssize_t len;
    ssize_t payload_len;
};

struct frame_t *g_frame;

// Some convenience constants
const size_t ETHER_PAYLOAD_START = (2*ETHER_ADDR_LEN) + ETHER_TYPE_LEN;
const size_t ETHER_PAYLOAD_LEN = ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN;

// Try to open the bpf device
int _open_dev(void)
{
    char buf[ 11 ] = { 0 };
    int bpf = 0;
    int i = 0;
    for(i = 0; i < 99; i++ )
    {
        sprintf( buf, "/dev/bpf%i", i );
        bpf = open( buf, O_RDWR );
        if( bpf != -1 ) {
            printf("Opened device /dev/bpf%i\n", i);
            break;
        }
    }
    if(bpf == -1) {
        printf("Cannot open any /dev/bpf* device, exiting\n");
        exit(1);
    }
    return bpf;
}

// Associate bpf device with a physical ethernet interface
void _assoc_dev(int bpf, char* interface)
{
    struct ifreq bound_if;
    strcpy(bound_if.ifr_name, interface);
    if(ioctl( bpf, BIOCSETIF, &bound_if ) > 0) {
        printf("Cannot bind bpf device to physical device %s, exiting\n", interface);
        exit(1);
    }
    printf("Bound bpf device to physical device %s\n", interface);
}

// // Set some options on the bpf device, then get the length of the kernel buffer
// int get_buf_len(int bpf)
// {
//     int buf_len = 1;
//     // activate immediate mode (therefore, buf_len is initially set to "1")
//     if( ioctl( bpf, BIOCIMMEDIATE, &buf_len ) == -1 ) {
//         printf("Cannot set IMMEDIATE mode of bpf device\n");
//         exit(1);
//     }
//     // request buffer length
//     if( ioctl( bpf, BIOCGBLEN, &buf_len ) == -1 ) {
//         printf("Cannot get bufferlength of bpf device\n");
//         exit(1);
//     }
//     printf("Buffer length of bpf device: %d\n", buf_len);
//     return buf_len;
// }


// Divide data across ethernet frames
void _write_frames (int bpf, unsigned char *databuf, size_t datalen, unsigned short protocol_type)
{
    size_t start = 0;
    // struct frame_t *frame = (struct frame_t *)malloc(ETHER_MAX_LEN);
    memset(g_frame, 0, ETHER_MAX_LEN);
    size_t bytes_to_send;
    ssize_t bytes_sent;
    memcpy(g_frame->header.ether_dhost, g_dest_mac, ETHER_HDR_LEN);
    memcpy(g_frame->header.ether_shost, g_src_mac, ETHER_HDR_LEN);
    g_frame->header.ether_type = htons(protocol_type);
    // printf("Rawsocket: Sending %lu bytes of type %X\n", datalen, protocol_type);
    do {
        // Clear frame
        bzero((void*)(g_frame+ETHER_PAYLOAD_START), ETHER_PAYLOAD_LEN);
        // Calculate remainder
        if((datalen - start) < ETHER_PAYLOAD_LEN) {
            bytes_to_send = datalen - start;
        } else {
            bytes_to_send = ETHER_PAYLOAD_LEN;
        }
        // Fill g_frame payload
        // printf("Copying payload from %lu, length %lu\n", start, bytes_to_send);
        memcpy(g_frame->payload, (void*)(databuf + start), bytes_to_send);
        g_frame->len = ETHER_HDR_LEN + bytes_to_send;
        // Note we don't add the four-byte CRC, the OS does this for us.
        // Neither do we fill packets with zeroes when the g_frame length is
        // below the minimum Ethernet g_frame length, the OS will do the
        // padding.

        // printf("Total g_frame length: %lu of maximum ethernet g_frame length %d\n", g_frame->len, ETHER_MAX_LEN - ETHER_CRC_LEN);
        bytes_sent = write(bpf, g_frame, g_frame->len);
        // Check results
        if(bytes_sent < 0 ) {
            perror("Error, perhaps device doesn't have IP address assigned?");
            exit(1);
        } else if(bytes_sent != g_frame->len) {
            printf("Error, only sent %ld bytes of %lu\n", bytes_sent, bytes_to_send);
        } else {
            // printf("Sending frame OK\n");
        }
        start += bytes_to_send;
    } while (start < datalen);
    // free(frame);
}

int rawsocket_connect(char *interface, unsigned char *src_mac, unsigned char *dest_mac) {
	ledpanel_tempbuffer =  (unsigned char*)malloc(1000000);
    printf("Rawsocket: Trying to talk to led panel on %s...\n", interface);
    memcpy(&g_src_mac, src_mac, ETHER_ADDR_LEN);
    memcpy(&g_dest_mac, dest_mac, ETHER_ADDR_LEN);
    g_bpf = _open_dev();
    g_frame = (struct frame_t *)malloc(ETHER_MAX_LEN);
    _assoc_dev(g_bpf, interface);
    return g_bpf;
}

void rawsocket_send(unsigned char *databuf, size_t datalen, unsigned short protocol_type) {
	_write_frames(g_bpf, databuf, datalen, protocol_type);
}

void rawsocket_disconnect() {
	free(ledpanel_tempbuffer);
    free(g_frame);
}

void ledpanel_handshake() {
    int testdata1_len = 510;
    memset(ledpanel_tempbuffer, 0, testdata1_len);
    rawsocket_send(ledpanel_tempbuffer, testdata1_len, 0x0700);
}

void ledpanel_scanline(int row, unsigned char *scanlinedata, int width) {
	// int testdata4_len = 1233;
	int packetsize = width * 3 + 1;
	ledpanel_tempbuffer[0] = row;
	memcpy(ledpanel_tempbuffer + 1, scanlinedata, width * 3);
    rawsocket_send(ledpanel_tempbuffer, packetsize, 0x5500);
}

void ledpanel_blit() {
    int testdata5_len = 1514;
    for(int i=0; i<testdata5_len; i++) {
    	ledpanel_tempbuffer[i] = i;
    }
    rawsocket_send(ledpanel_tempbuffer, testdata5_len, 0x01ff);
}
