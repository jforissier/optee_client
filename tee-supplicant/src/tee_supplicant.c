/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <teec_trace.h>
#include <teec_ta_load.h>
#include <tee_supp_fs.h>
#include <rpmb.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

#define RPC_NUM_PARAMS	2

#define RPC_BUF_SIZE	(sizeof(struct tee_iocl_supp_send_arg) + \
			 RPC_NUM_PARAMS * sizeof(struct tee_ioctl_param))

#define RPC_CMD_LOAD_TA		0
#define RPC_CMD_RPMB		1
#define RPC_CMD_FS		2

union tee_rpc_invoke {
	uint64_t buf[RPC_BUF_SIZE / sizeof(uint64_t)];
	struct tee_iocl_supp_recv_arg recv;
	struct tee_iocl_supp_send_arg send;
};

struct tee_rpc_ta {
	TEEC_UUID uuid;
	uint32_t supp_ta_handle;
};

static int read_request(int fd, union tee_rpc_invoke *request);
static int write_response(int fd, union tee_rpc_invoke *request);
static void free_param(TEEC_SharedMemory *shared_mem);

/* Get parameter allocated by secure world */
static int get_param(union tee_rpc_invoke *request, const uint32_t idx,
		     TEEC_SharedMemory *shm)
{
	struct tee_ioctl_param *params;

	if (idx >= request->recv.num_params)
		return -1;

	params = (struct tee_ioctl_param *)(&request->send + 1);
	switch (params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		break;
	default:
		return -1;
	}

	memset(shm, 0, sizeof(*shm));
	shm->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shm->size = params[idx].u.memref.size;
	shm->fd = params[idx].u.memref.shm_fd;
	if (shm->fd == -1)
		return 0;
	shm->buffer = mmap(NULL, shm->size, PROT_READ | PROT_WRITE, MAP_SHARED,
			   shm->fd, params[idx].u.memref.shm_offs);
	params[idx].u.memref.shm_fd = -1; /* fd taken */
	if (shm->buffer == (void *)MAP_FAILED) {
		EMSG("failed to mmap parameter (fd %d, offs 0x%" PRIx64 ", idx %d): %s",
		     shm->fd, (uint64_t)params[idx].u.memref.shm_offs, idx,
		     strerror(errno));
		close(shm->fd);
		shm->fd = -1;
		return -1;
	}
	return 0;
}

/* Release parameter recieved from get_param or alloc_param */
static void free_param(TEEC_SharedMemory *shared_mem)
{
	if (!shared_mem->buffer)
		return;
	if (munmap(shared_mem->buffer, shared_mem->size) != 0)
		EMSG("munmap(%p, %zu) failed - Error = %s",
		     shared_mem->buffer, shared_mem->size,
		     strerror(errno));
	close(shared_mem->fd);
}

static void process_fs(union tee_rpc_invoke *request)
{
	TEEC_SharedMemory shm;

	if (request->recv.num_params != 1 || get_param(request, 0, &shm)) {
		request->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	tee_supp_fs_process(shm.buffer, shm.size);
	request->send.ret = TEEC_SUCCESS;;

	free_param(&shm);
}

static void load_ta(union tee_rpc_invoke *request)
{
	int ta_found = 0;
	size_t size = 0;
	struct tee_rpc_ta *cmd;
	TEEC_SharedMemory shm_cmd = { 0 };
	TEEC_SharedMemory shm_ta = { 0 };

	if (request->recv.num_params != 2 || get_param(request, 0, &shm_cmd) ||
	    get_param(request, 1, &shm_ta)) {
		request->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}
	cmd = (struct tee_rpc_ta *)shm_cmd.buffer;

	size = shm_ta.size;
	ta_found = TEECI_LoadSecureModule("optee_armtz", &cmd->uuid,
					  shm_ta.buffer, &size);
	if (ta_found == TA_BINARY_FOUND) {
		struct tee_ioctl_param *params =
			(struct tee_ioctl_param *)(&request->recv + 1);

		params[1].u.memref.size = size;
		request->send.ret = TEEC_SUCCESS;
	} else {
		EMSG("  TA not found");
		request->send.ret = TEEC_ERROR_ITEM_NOT_FOUND;
	}

	free_param(&shm_cmd);
	free_param(&shm_ta);
}

/* How many device sequence numbers will be tried before giving up */
#define MAX_DEV_SEQ	10

static int open_dev(const char *devname)
{
	struct tee_ioctl_version_data vers;
	int fd;

	fd = open(devname, O_RDWR);
	if (fd < 0)
		return -1;

	if (ioctl(fd, TEE_IOC_VERSION, &vers))
		goto err;

	/* Only OP-TEE supported */
	if (vers.impl_id != TEE_IMPL_ID_OPTEE)
		goto err;

	DMSG("using device \"%s\"", devname);
	return fd;
err:
	close(fd);
	return -1;
}

static int get_dev_fd(void)
{
	int fd;
	char name[PATH_MAX];
	size_t n;

	for (n = 0; n < MAX_DEV_SEQ; n++) {
		snprintf(name, sizeof(name), "/dev/teepriv%zu", n);
		fd = open_dev(name);
		if (fd >= 0)
			return fd;
	}
	return -1;
}

static void usage(void)
{
	fprintf(stderr, "usage: tee-supplicant [<device-name>]");
	exit(1);
}

static void process_rpmb(union tee_rpc_invoke *request)
{
	TEEC_SharedMemory req, rsp;

	INMSG();
	if (request->recv.num_params != 2 || get_param(request, 0, &req) ||
	    get_param(request, 1, &rsp)) {
		request->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	request->send.ret = rpmb_process_request(req.buffer, req.size,
						 rsp.buffer, rsp.size);

	free_param(&req);
	free_param(&rsp);
out:
	OUTMSG();
}

int main(int argc, char *argv[])
{
	int fd;
	union tee_rpc_invoke request;
	int ret;

	if (argc > 2)
		usage();
	if (argc == 2) {
		fd = open_dev(argv[1]);
		if (fd < 0) {
			EMSG("failed to open \"%s\"", argv[1]);
			exit(EXIT_FAILURE);
		}
	} else {
		fd = get_dev_fd();
		if (fd < 0) {
			EMSG("failed to find an OP-TEE supplicant device");
			exit(EXIT_FAILURE);
		}
	}

	if (tee_supp_fs_init() != 0) {
		EMSG("error tee_supp_fs_init");
		exit(EXIT_FAILURE);
	}

	/* major failure on read kills supplicant, malformed data will not */
	do {
		DMSG("looping");
		memset(&request, 0, sizeof(request));
		request.recv.num_params = RPC_NUM_PARAMS;
		ret = read_request(fd, &request);
		if (ret == 0) {
			switch (request.recv.func) {
			case RPC_CMD_LOAD_TA:
				load_ta(&request);
				break;

			case RPC_CMD_FS:
				process_fs(&request);
				break;

			case RPC_CMD_RPMB:
				process_rpmb(&request);
				break;

			default:
				EMSG("Cmd [0x%" PRIx32 "] not supported",
				     request.recv.func);
				/* Not supported. */
				break;
			}
			IMSG("");

			ret = write_response(fd, &request);
		}
	} while (ret >= 0);

	close(fd);

	return EXIT_FAILURE;
}

static int read_request(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

	data.buf_ptr = (uintptr_t)request;
	data.buf_len = sizeof(*request);
	if (ioctl(fd, TEE_IOC_SUPPL_RECV, &data)) {
		EMSG("TEE_IOC_SUPPL_RECV: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static int write_response(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;
	struct tee_ioctl_param *params;
	size_t n;

	/* Close file descriptors not claimed */
	params = (struct tee_ioctl_param *)(&request->send + 1);
	for (n = 0; n < request->send.num_params; n++) {
		switch (params[n].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			if (params[n].u.memref.shm_fd != -1)
				close(params[n].u.memref.shm_fd);
			params[n].u.memref.shm_fd = -1;
			break;
		default:
			break;
		}
	}
	IMSG("");

	data.buf_ptr = (uintptr_t)&request->send;
	data.buf_len = sizeof(struct tee_iocl_supp_send_arg) +
		       sizeof(struct tee_ioctl_param) *
				request->send.num_params;
	if (ioctl(fd, TEE_IOC_SUPPL_SEND, &data)) {
		EMSG("TEE_IOC_SUPPL_SEND: %s", strerror(errno));
		return -1;
	}
	return 0;
}
