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

unsigned char src_mac[ETHER_ADDR_LEN] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
unsigned char dest_mac[ETHER_ADDR_LEN]  = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

struct frame_t {
    struct ether_header header;
    unsigned char payload[ETHER_MAX_LEN - ETHER_HDR_LEN];
    ssize_t len;
    ssize_t payload_len;
};

// Some convenience constants
const size_t ETHER_PAYLOAD_START = (2*ETHER_ADDR_LEN) + ETHER_TYPE_LEN;
const size_t ETHER_PAYLOAD_LEN = ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN;

// Try to open the bpf device
int open_dev(void)
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
void assoc_dev(int bpf, char* interface)
{
    struct ifreq bound_if;
    strcpy(bound_if.ifr_name, interface);
    if(ioctl( bpf, BIOCSETIF, &bound_if ) > 0) {
        printf("Cannot bind bpf device to physical device %s, exiting\n", interface);
        exit(1);
    }
    printf("Bound bpf device to physical device %s\n", interface);
}

// Set some options on the bpf device, then get the length of the kernel buffer
int get_buf_len(int bpf)
{
    int buf_len = 1;
    // activate immediate mode (therefore, buf_len is initially set to "1")
    if( ioctl( bpf, BIOCIMMEDIATE, &buf_len ) == -1 ) {
        printf("Cannot set IMMEDIATE mode of bpf device\n");
        exit(1);
    }
    // request buffer length
    if( ioctl( bpf, BIOCGBLEN, &buf_len ) == -1 ) {
        printf("Cannot get bufferlength of bpf device\n");
        exit(1);
    }
    printf("Buffer length of bpf device: %d\n", buf_len);
    return buf_len;
}

// Write a single ethernet frame with test data
void write_single_frame(int bpf)
{
    ssize_t data_length = 0x4F;
    struct frame_t frame;
    memcpy(frame.header.ether_dhost, dest_mac, ETHER_HDR_LEN);
    memcpy(frame.header.ether_shost, src_mac, ETHER_HDR_LEN);
    frame.header.ether_type = 0x00;
    frame.len = (2*ETHER_ADDR_LEN) + ETHER_TYPE_LEN + data_length;
    // Fill frame with ramp
    unsigned char j;
    for (j = 0; j < data_length; j++) {
        frame.payload[j] = j;
    }
    ssize_t bytes_sent;
    bytes_sent = write(bpf, &frame, frame.len);
    if(bytes_sent > 0) {
        printf("Bytes sent: %ld\n", bytes_sent);
    } else {
        perror("Whoops! Does the device actually have an IP address?");
        exit(1);
    }
}

// Create a simple ramp so we can check the splitting of data across frames on
// the other side (using tcpdump or somesuch)
unsigned char* make_testdata(int len)
{
    unsigned char *testdata = (unsigned char*)malloc(len);
    int i;
    unsigned char j = 0;
    for(i = 0; i < len; i++) {
        testdata[i] = j;
        j++;
        if(j < sizeof(char)) {
            j = 0;
        }
    }
    return testdata;
}

// Divide data across ethernet frames
void write_frames (int bpf, const unsigned char *databuf, size_t datalen, unsigned short protocol_type)
{
    size_t start = 0;
    struct frame_t *frame = (struct frame_t *)malloc(ETHER_MAX_LEN);
    size_t bytes_to_send;
    ssize_t bytes_sent;
    memcpy(frame->header.ether_dhost, dest_mac, ETHER_HDR_LEN);
    memcpy(frame->header.ether_shost, src_mac, ETHER_HDR_LEN);
    frame->header.ether_type = htons(protocol_type);
   printf("protocol_type = %X, frame->header.ether_type = %X\n", protocol_type, frame->header.ether_type);
    do {
        // Clear frame
        bzero((void*)(frame+ETHER_PAYLOAD_START), ETHER_PAYLOAD_LEN);
        // Calculate remainder
        if((datalen - start) < ETHER_PAYLOAD_LEN) {
            bytes_to_send = datalen - start;
        } else {
            bytes_to_send = ETHER_PAYLOAD_LEN;
        }
        // Fill frame payload
        printf("Copying payload from %lu, length %lu\n", start, bytes_to_send);
        memcpy(frame->payload, (void*)(databuf + start), bytes_to_send);
        frame->len = ETHER_HDR_LEN + bytes_to_send;
        // Note we don't add the four-byte CRC, the OS does this for us.
        // Neither do we fill packets with zeroes when the frame length is
        // below the minimum Ethernet frame length, the OS will do the
        // padding.
        printf("Total frame length: %lu of maximum ethernet frame length %d\n",
            frame->len, ETHER_MAX_LEN - ETHER_CRC_LEN);
        bytes_sent = write(bpf, frame, frame->len);
        // Check results
        if(bytes_sent < 0 ) {
            perror("Error, perhaps device doesn't have IP address assigned?");
            exit(1);
        } else if(bytes_sent != frame->len) {
            printf("Error, only sent %ld bytes of %lu\n", bytes_sent, bytes_to_send);
        } else {
            printf("Sending frame OK\n");
        }
        start += bytes_to_send;
    } while (start < datalen);
    free(frame);
}

void test_ledpanel(char *interface) {
    printf("Trying to talk to led panel on %s...\n", interface);

    int bpf;
    int buf_len;

    bpf = open_dev();
    printf("bpf=%X\n", bpf);
    assoc_dev(bpf, interface);
    buf_len = get_buf_len(bpf);

    //read_single_frame(bpf, buf_len);
    //read_frames(bpf, buf_len);

    int testdata1_len = 510;
    int testdata4_len = 1233;
    int testdata5_len = 1514;

    float ph = 0;

    unsigned char* testdata1 = make_testdata(testdata1_len);
    unsigned char* testdata4 = make_testdata(testdata4_len);
    unsigned char* testdata5 = make_testdata(testdata5_len);
    write_frames(bpf, testdata1, testdata1_len, 0x0700);
    while(true) {
        for(int line = 0; line<64; line++) {
            memset(testdata4, 0, testdata4_len);
            testdata4[0] = line;

            int o = 1;
            for(int j=0; j<64; j++) {

                float rr = sin((float)j / 19.1 + ph / 3.6) * cos((float)line / 9.1 + ph / 6.5);
                float gg = cos((float)line / 11.5 - sin(ph / 5.4)) * cos((float)j / 19.3 + ph / 6.3);
                float bb = sin((float)j / 17.3 + line / 13.1 - ph / 9.3) * gg;

                testdata4[o++] = fmax(0, fmin(255, (int)(12.0f + 64.0f * rr)));
                testdata4[o++] = fmax(0, fmin(255, (int)(12.0f + 64.0f * gg)));
                testdata4[o++] = fmax(0, fmin(255, (int)(12.0f + 64.0f * bb)));
            }
            write_frames(bpf, testdata4, testdata4_len, 0x5500);
        }
        write_frames(bpf, testdata5, testdata5_len, 0x01ff);
        usleep(16000); // 16ms delay
        ph += 0.6f;
    }
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Syntax: ./test1 [interface]");
        return 1;
    }

    char *interface = argv[1];
    test_ledpanel(interface);
    return 0;
};
