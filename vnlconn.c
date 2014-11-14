#include "vnlconn.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
/* 90904102 */

struct VnlConn* vnl_open(uint16_t topoid, const char* host) {
	char connscript[32];
	snprintf(connscript,32,"vnltopo%u.sh",topoid);
	if (0 != access(connscript,F_OK)) { fprintf(stderr,"%s does not exist\n",connscript); exit(1); }
	if (0 != chmod(connscript,0700)) { perror("chmod(connscript)"); exit(1); }

	int pipe1[2]; int pipe2[2];
	if (0 != pipe(pipe1)) { perror("pipe(pipe1)"); exit(1); }
	if (0 != pipe(pipe2)) { perror("pipe(pipe2)"); exit(1); }

	pid_t cpid = fork();
	if (-1 == cpid) { perror("fork"); exit(1); }
	if (cpid == 0) {
		if (-1 == dup2(pipe1[1], 1)) { perror("dup2(pipe1[1])"); exit(1); }
		if (-1 == dup2(pipe2[0], 0)) { perror("dup2(pipe2[0])"); exit(1); }
		close(pipe1[0]); close(pipe2[1]);
		char* pargv[4];
		pargv[0] = connscript;
		pargv[1] = (char*)host;
		pargv[2] = "run";
		pargv[3] = NULL;
		execve(connscript,pargv,NULL);
		return NULL;
	} else {
		fprintf(stderr,"Virtual Network Lab, connection open\n");
		struct VnlConn* vc = calloc(1, sizeof(struct VnlConn));
		vc->ssh_pid = cpid;
		vc->read_fd = pipe1[0]; close(pipe1[1]);
		vc->write_fd = pipe2[1]; close(pipe2[0]);
		return vc;
	}
}

ssize_t vnl_read(struct VnlConn* vc, void* buf, size_t count) {
	vnl_checkconn(vc);
	return read(vc->read_fd,buf,count);
}

ssize_t vnl_write(struct VnlConn* vc, const void* buf, size_t count) {
	vnl_checkconn(vc);
	return write(vc->write_fd,buf,count);
}

void vnl_close(struct VnlConn* vc) {
	close(vc->read_fd); close(vc->write_fd);
	kill(vc->ssh_pid,SIGKILL);
	free(vc);
}

void vnl_checkconn(struct VnlConn* vc) {
	int ret, status;
	ret = waitpid(vc->ssh_pid,&status,WNOHANG);
	if (ret != 0) {
		fprintf(stderr,"Virtual Network Lab, connection close\n");
		exit(0);
	}
}

