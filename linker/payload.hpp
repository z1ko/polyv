#pragma once

/// All function with this attribute are stored in the encrypted section
#define POLYV_ENCRYPTED __attribute__ ((section (".encrypted")))

static __attribute__ ((section (".key"))) char key[4];

int POLYV_ENCRYPTED add1(int x);
int POLYV_ENCRYPTED add2(int x);
int POLYV_ENCRYPTED add3(int x);;
int POLYV_ENCRYPTED add4(int x);