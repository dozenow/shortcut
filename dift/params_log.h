#ifndef PARAMS_LOG_H
#define PARAMS_LOG_H
struct open_params {
	int flags;
	int mode;
	char filename[0];
};

struct read_params {
	int fd;
	char* buf; 
	int size;
};

#endif
