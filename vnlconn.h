/*
vnlconn.h
Virtual Network Lab connection for VNS client

Junxiao Shi, University of Arizona
*/

#ifndef VNLCONN_H
#define VNLCONN_H
#include <stdint.h>
#include <unistd.h>

struct VnlConn {
	pid_t ssh_pid;
	int read_fd;
	int write_fd;
};

struct VnlConn* vnl_open(uint16_t topoid, const char* host);
ssize_t vnl_read(struct VnlConn* vc, void* buf, size_t count);
ssize_t vnl_write(struct VnlConn* vc, const void* buf, size_t count);
void vnl_close(struct VnlConn* vc);
void vnl_checkconn(struct VnlConn* vc);

#endif//VNLCONN_H

