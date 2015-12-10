/*
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

#include <rpmb.h>
#include <tee_client_api.h>
#include <teec_trace.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/mmc/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef RPMB_EMU
#include <stdarg.h>
#endif

/*
 * The following definitions must be in sync with the secure side
 */

/* Request */
struct rpmb_req {
	uint16_t cmd;
#define RPMB_CMD_DATA_REQ      0x00
#define RPMB_CMD_GET_DEV_INFO  0x01
	uint16_t dev_id;
	uint16_t block_count;
	/* Optional data frames (rpmb_data_frame) follow */
};
#define RPMB_REQ_DATA(req) ((void *)((struct rpmb_req *)(req) + 1))

/* Response to device info request */
struct rpmb_dev_info {
	uint8_t cid[16];
	uint8_t rpmb_size_mult;	/* EXT CSD-slice 168 "RPMB Size" */
	uint8_t rel_wr_sec_c;	/* EXT CSD-slice 222 "Reliable Write Sector */
				/* Count" */
	uint8_t ret_code;
#define RPMB_CMD_GET_DEV_INFO_RET_OK     0x00
#define RPMB_CMD_GET_DEV_INFO_RET_ERROR  0x01
};

/*
 * End of common definitions
 */

struct rpmb_data_frame {
	uint8_t stuff_bytes[196];
	uint8_t key_mac[32];
	uint8_t data[256];
	uint8_t nonce[16];
	uint32_t write_counter;
	uint16_t address;
	uint16_t block_count;
	uint16_t op_result;
#define RPMB_RESULT_OK                              0x00
#define RPMB_RESULT_GENERAL_FAILURE                 0x01
#define RPMB_RESULT_AUTH_FAILURE                    0x02
#define RPMB_RESULT_COUNTER_FAILURE                 0x03
#define RPMB_RESULT_ADDRESS_FAILURE                 0x04
#define RPMB_RESULT_WRITE_FAILURE                   0x05
#define RPMB_RESULT_READ_FAILURE                    0x06
#define RPMB_RESULT_AUTH_KEY_NOT_PROGRAMMED         0x07
#define RPMB_RESULT_MASK                            0x3F
#define RPMB_RESULT_WR_CNT_EXPIRED                  0x80
	uint16_t msg_type;
#define RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM          0x0001
#define RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ    0x0002
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE           0x0003
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_READ            0x0004
#define RPMB_MSG_TYPE_REQ_RESULT_READ	            0x0005
#define RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM         0x0100
#define RPMB_MSG_TYPE_RESP_WRITE_COUNTER_VAL_READ   0x0200
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE          0x0300
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_READ           0x0400
};

/*
 * ioctl() interface
 * See: uapi/linux/major.h, linux/mmc/core.h
 */

#define MMC_BLOCK_MAJOR	179

/* mmc_ioc_cmd.opcode */
#define MMC_READ_MULTIPLE_BLOCK		18
#define MMC_WRITE_MULTIPLE_BLOCK	25

/* mmc_ioc_cmd.flags */
#define MMC_RSP_PRESENT	(1 << 0)
#define MMC_RSP_CRC	(1 << 2) /* Expect valid CRC */
#define MMC_RSP_OPCODE	(1 << 4) /* Response contains opcode */
#define MMC_RSP_R1      (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_CMD_ADTC	(1 << 5) /* Addressed data transfer command */

#define MMC_CMD23_ARG_REL_WR	(1 << 31) /* CMD23 reliable write */

#ifndef RPMB_EMU

#define IOCTL(fd, request, ...) ioctl((fd), (request), ##__VA_ARGS__)

/* Open and/or return file descriptor to RPMB partition of device dev_id */
static int mmc_rpmb_fd(uint16_t dev_id)
{
	static int id;
	static int fd = -1;
	char path[21] = { 0, };

	if (fd < 0) {
		snprintf(path, sizeof(path) - 1, "/dev/mmcblk%urpmb", dev_id);
		fd = open(path, O_RDWR);
		if (fd < 0) {
			EMSG("Could not open %s (%s)", path, strerror(errno));
			return -1;
		}
		id = dev_id;
	}
	if (id != dev_id) {
		EMSG("Only one MMC device is supported");
		return -1;
	}
	return fd;
}

#else

#define IOCTL(fd, request, ...) ioctl_emu((fd), (request), ##__VA_ARGS__)

/* A crude emulation of the MMC ioctls we need for RPMB */
static int ioctl_emu(int fd, unsigned long request, ...)
{
	struct mmc_ioc_cmd *cmd;
	va_list ap;
	(void)fd;

	if (request != MMC_IOC_CMD) {
		EMSG("Unsupported ioctl: 0x%lx", request);
		return -1;
	}

	va_start(ap, request);
	cmd = va_arg(ap, struct mmc_ioc_cmd *);
	va_end(ap);

	switch (cmd->opcode) {
	case MMC_WRITE_MULTIPLE_BLOCK:
		DMSG("MMC_WRITE_MULTIPLE_BLOCK");
		break;

	case MMC_READ_MULTIPLE_BLOCK:
		DMSG("MMC_READ_MULTIPLE_BLOCK");
		break;

	default:
		EMSG("Unsupported opcode: 0x%04x", cmd->opcode);
		return -1;
	}

	return 0;
}

static int mmc_rpmb_fd(uint16_t dev_id)
{
	(void)dev_id;

	/* Any value != -1 will do in test mode */
	return 0;
}

#endif /* ! RPMB_EMU */

static uint32_t rpmb_data_req(int fd, struct rpmb_data_frame *req_frm,
			      size_t req_nfrm, struct rpmb_data_frame *rsp_frm,
			      size_t rsp_nfrm)
{
	int st;
	size_t i;
	uint16_t msg_type = ntohs(req_frm->msg_type);
	struct mmc_ioc_cmd cmd = {
		.blksz = 512,
		.blocks = req_nfrm,
		.data_ptr = (uintptr_t)req_frm,
		.flags = MMC_RSP_R1 | MMC_CMD_ADTC,
		.opcode = MMC_WRITE_MULTIPLE_BLOCK,
		.write_flag = 1
		};

	for (i = 1; i < req_nfrm; i++) {
		if (req_frm[i].msg_type != msg_type) {
			EMSG("All request frames shall be of the same type");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
	}

	DMSG("Req: %zu frames of type 0x%04x", req_nfrm, msg_type);
	DMSG("Rsp: %zu frames", rsp_nfrm);

	switch(msg_type) {
	case RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM:
	case RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE:
		if (rsp_nfrm != 1) {
			EMSG("Expected only one response frame");
			return TEEC_ERROR_BAD_PARAMETERS;
		}

		/* Send write request frame(s) */
		cmd.write_flag |= MMC_CMD23_ARG_REL_WR;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEEC_ERROR_GENERIC;

		/* Send result request frame */
		memset(rsp_frm, 0, 1);
		rsp_frm->msg_type = htons(RPMB_MSG_TYPE_REQ_RESULT_READ);
		cmd.data_ptr = (uintptr_t)rsp_frm;
		cmd.write_flag &= ~MMC_CMD23_ARG_REL_WR;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEEC_ERROR_GENERIC;

		/* Read response frame */
		cmd.opcode = MMC_READ_MULTIPLE_BLOCK;
		cmd.write_flag = 0;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEEC_ERROR_GENERIC;
		break;

	case RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ:
		if (rsp_nfrm != 1) {
			EMSG("Expected only one response frame");
			return TEEC_ERROR_BAD_PARAMETERS;
		}

		/* Fall through */
	case RPMB_MSG_TYPE_REQ_AUTH_DATA_READ:
		if (req_nfrm != 1) {
			EMSG("Expected only one request frame");
			return TEEC_ERROR_BAD_PARAMETERS;
		}

		/* Send request frame */
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEEC_ERROR_GENERIC;

		/* Read response frames */
		cmd.data_ptr = (uintptr_t)rsp_frm;
		cmd.opcode = MMC_READ_MULTIPLE_BLOCK;
		cmd.write_flag = 0;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEEC_ERROR_GENERIC;
		break;

	default:
		EMSG("Unsupported message type: %d", msg_type);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static uint32_t rpmb_get_dev_info(int fd, struct rpmb_dev_info *info)
{
	/* TODO use ioctl() interface */
	(void)fd;

	/* This is the CID of the actual eMMC chip if my HiKey board */
	static const uint8_t test_cid[] = { /* MID (Manufacturer ID): Micron */
					    0xfe,
					    /* CBX (Device/BGA): BGA */
					    0x01,
					    /* OID (OEM/Application ID) */
					    0x4e,
					     /* PNM (Product name) "MMC04G" */
					    0x4d, 0x4d, 0x43, 0x30, 0x34, 0x47,
					    /* PRV (Product revision): 4.2 */
					    0x42,
					    /* PSN (Product serial number) */
					    0xc8, 0xf6, 0x55, 0x2a,
					    /*
					     * MDT (Manufacturing date):
					     * June, 2014
					     */
					    0x61,
					    /* (CRC7 (0xA) << 1) | 0x1 */
					    0x15 };

	INMSG();

	memcpy(info->cid, test_cid, sizeof(info->cid));
	info->rel_wr_sec_c = 0x01;
	info->rpmb_size_mult = 0x01;

	info->ret_code = RPMB_CMD_GET_DEV_INFO_RET_OK;
	OUTMSG();

	return TEEC_SUCCESS;
}

/*
 * req is one struct rpmb_req followed by one or more struct rpmb_data_frame
 * rsp is either one struct rpmb_dev_info or one or more struct rpmb_data_frame
 */
uint32_t rpmb_process_request(void *req, size_t req_size, void *rsp,
			      size_t rsp_size)
{
	struct rpmb_req *sreq = req;
	size_t req_nfrm;
	size_t rsp_nfrm;
	uint32_t res;
	int fd;

	if (req_size < sizeof(*sreq))
		return TEEC_ERROR_BAD_PARAMETERS;

	fd = mmc_rpmb_fd(sreq->dev_id);
	if (fd < 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	switch (sreq->cmd) {
	case RPMB_CMD_DATA_REQ:
		req_nfrm = (req_size - sizeof(struct rpmb_req)) / 512;
		rsp_nfrm = rsp_size / 512;
		res = rpmb_data_req(fd, RPMB_REQ_DATA(req), req_nfrm, rsp, rsp_nfrm);
		break;

	case RPMB_CMD_GET_DEV_INFO:
		if (req_size != sizeof(struct rpmb_req) ||
		    rsp_size != sizeof(struct rpmb_dev_info)) {
			EMSG("Invalid req/rsp size");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
		res = rpmb_get_dev_info(fd, (struct rpmb_dev_info *)rsp);
		break;

	default:
		EMSG("Unsupported RPMB command: %d", sreq->cmd);
		res = TEEC_ERROR_BAD_PARAMETERS;
		break;
	}

	return res;
}
