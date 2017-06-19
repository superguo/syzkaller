#!/usr/bin/env bash
# Copyright 2015 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Assuming x86 host, you also need to install:
# sudo apt-get install gcc-aarch64-linux-gnu gcc-powerpc64le-linux-gnu

if [ "$LINUX" == "" ]; then
	if [ "$ANDROID" == "" ]; then
		echo "usage: make extract LINUX=/linux/checkout"
		echo "OR: make extract ANDROID=/linux/checkout"
		echo "OR: make extract ANDROID=/linux/checkout EMULATOR=yes"
		exit 1
	else
		LINUX=$ANDROID
		BUILD_FOR_ANDROID=yes
		if [ "$EMULATOR" == "yes" ]; then
			BUILD_FOR_ANDROID_EMULATOR=yes
		else
			BUILD_FOR_ANDROID_EMULATOR=no
		fi
	fi
else
	BUILD_FOR_ANDROID=no
fi

UPSTREAM_FILES="sys/bpf.txt sys/dri.txt sys/fuse.txt sys/input.txt sys/ipc.txt
		sys/key.txt sys/kvm.txt sys/loop.txt sys/perf.txt sys/random.txt
		sys/sndcontrol.txt sys/sndseq.txt sys/sndtimer.txt sys/socket.txt
		sys/socket_alg.txt sys/socket_bluetooth.txt sys/socket_inet.txt
		sys/socket_inet_icmp.txt sys/socket_inet_sctp.txt sys/socket_inet_tcp.txt
		sys/socket_inet_udp.txt sys/socket_kcm.txt sys/socket_key.txt
		sys/socket_netlink.txt sys/socket_netrom.txt sys/socket_nfc.txt
		sys/socket_unix.txt sys/sys.txt sys/test.txt sys/tty.txt sys/tun.txt
		sys/vnet.txt"

ANDROID_FILES="sys/tlk_device.txt"
ANDROID_EMULATOR_FILES="sys/binder.txt sys/tty.txt \
	sys/key.txt sys/fuse.txt \
	sys/input.txt \
	sys/random.txt \
	sys/ion.txt \
	sys/ashmem.txt"

if [ "$BUILD_FOR_ANDROID" == "no" ]; then
	FILES="$UPSTREAM_FILES"
elif [ "$BUILD_FOR_ANDROID_EMULATOR" == "yes" ]; then
	FILES="$ANDROID_EMULATOR_FILES"
else
	FILES="$ANDROID_FILES"
fi

CONFIG:=defconfig

generate_arch() {
	echo generating arch $1...
	echo "cd $LINUX; make $CONFIG"
	if [ "$BUILD_FOR_ANDROID" == "yes" ]; then
		CROSS_COMPILE=$3-linux-android-
	else
		CROSS_COMPILE=$3-linux-gnu-
	fi
	OUT=`(cd $LINUX; make ARCH=$2 CROSS_COMPILE=$CROSS_COMPILE $CONFIG 2>&1)`
	if [ $? -ne 0 ]; then
		echo "$OUT"
		exit 1
	fi
	echo "cd $LINUX; make"
	OUT=`(cd $LINUX; make ARCH=$2 CROSS_COMPILE=$CROSS_COMPILE init/main.o 2>&1)`
	if [ $? -ne 0 ]; then
		echo "$OUT"
		exit 1
	fi
	for F in $FILES; do
		echo "extracting from $F"
		bin/syz-extract -arch $1 -linux "$LINUX" -linuxbld "$LINUXBLD" $F
		if [ $? -ne 0 ]; then
			exit 1
		fi
	done
	echo
}


generate_arch amd64 x86_64 x86_64
if [ "$BUILD_FOR_ANDROID" == "no" ]; then
	generate_arch ppc64le powerpc powerpc64le
	generate_arch arm64 arm64 aarch64
fi

