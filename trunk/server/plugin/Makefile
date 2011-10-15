CC				?= gcc
CFLAGS			?= -Wall -fPIC -g

PROTO_CHECK_C	= protocol_check.c ../common/pcap.c
PROTO_CHECK_O	= protocol_check.o pcap.o

DS_BITS_CHECK_C	= ds_bits_check.c ../common/pcap.c
DS_BITS_CHECK_O	= ds_bits_check.o pcap.o

DEAUTH_DETECT_C	= deauth_detect.c ../common/pcap.c ../common/utils.c
DEAUTH_DETECT_O	= deauth_detect.o pcap.o utils.o

IE_C			= IEs.c ../common/pcap.c
IE_O			= IEs.o pcap.o

default: all

all: clean protocol_check ds_bits_check deauth_detect ie

ie:
	$(CC) $(CFLAGS) -c $(IE_C)
	$(CC) -shared -Wl,-soname,ie.so.1 -o ie.so.1.0   $(IE_O)


deauth_detect:
	$(CC) $(CFLAGS) -c $(DEAUTH_DETECT_C)
	$(CC) -shared -Wl,-soname,deauth_detect.so.1 -o deauth_detect.so.1.0   $(DEAUTH_DETECT_O)

ds_bits_check:
	$(CC) $(CFLAGS) -c $(DS_BITS_CHECK_C)
	$(CC) -shared -Wl,-soname,ds_bits_check.so.1 -o ds_bits_check.so.1.0   $(DS_BITS_CHECK_O)
	
protocol_check:
	$(CC) $(CFLAGS) -c $(PROTO_CHECK_C)
	$(CC) -shared -Wl,-soname,protocol_check.so.1 -o protocol_check.so.1.0   $(PROTO_CHECK_O)

clean:
	rm -f *.o *.so.*
	
