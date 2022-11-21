#pragma once
#include <Windows.h>

#define MAX_REDIR_SIZE 32

#define LDS_CLEAN 0
#define LDS_LOADED 1
#define LDS_RUN 2
#define LDS_ATTACHED 3

typedef struct _min_hdr {
	BYTE redir[MAX_REDIR_SIZE];
	BYTE load_status;
} min_hdr_t;
