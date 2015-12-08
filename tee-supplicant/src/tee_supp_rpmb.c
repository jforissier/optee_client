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

#include <tee_supp_rpmb.h>
#include <tee_client_api.h>
#include <teec_trace.h>
#include <string.h>

/*
 * The following definitions must be in sync with the secure side
 */

struct rpmb_req {
	uint16_t cmd;
	uint16_t dev_id;
	uint16_t block_count;
	/* Data follows */
};

#define TEE_RPMB_REQ_DATA(req) ((void *)((struct rpmb_req *)(req) + 1))

/* RPMB internal commands */
#define RPMB_CMD_DATA_REQ      0x00
#define RPMB_CMD_GET_DEV_INFO  0x01

#define RPMB_EMMC_CID_SIZE 16
struct rpmb_dev_info {
	uint8_t cid[RPMB_EMMC_CID_SIZE];
	/* EXT CSD-slice 168 "RPMB Size" */
	uint8_t rpmb_size_mult;
	/* EXT CSD-slice 222 "Reliable Write Sector Count" */
	uint8_t rel_wr_sec_c;
	/* Check the ret code and accept the data only if it is OK. */
	uint8_t ret_code;
};

/* Error codes for rpmb_dev_info.ret_code */
#define RPMB_CMD_GET_DEV_INFO_RET_OK     0x00
#define RPMB_CMD_GET_DEV_INFO_RET_ERROR  0x01

/*
 * End of common definitions
 */

static uint32_t rpmb_data_req(struct rpmb_req *req, size_t size)
{
	(void)req;
	(void)size;

	return TEEC_ERROR_NOT_IMPLEMENTED;
}

static uint32_t rpmb_get_dev_info(struct rpmb_req *req, size_t req_size,
				  struct rpmb_dev_info *info, size_t info_size)
{
	if (req_size != sizeof(*req) || info_size != sizeof(*info))
		return TEEC_ERROR_BAD_PARAMETERS;

	strncpy((char *)info->cid, "TEST-ID-01234567", sizeof(info->cid));

	info->rel_wr_sec_c = 0x01;
	info->rpmb_size_mult = 0x01;

	info->ret_code = RPMB_CMD_GET_DEV_INFO_RET_OK;

	return TEEC_SUCCESS;
}

uint32_t rpmb_process_request(void *req, size_t req_size, void *rsp,
			      size_t rsp_size)
{
	struct rpmb_req *sreq = req;
	struct rpmb_dev_info *dev_info;
	uint32_t res;

	if (req_size < sizeof(*sreq))
		return TEEC_ERROR_BAD_PARAMETERS;

	switch (sreq->cmd) {
	case RPMB_CMD_DATA_REQ:
		res = rpmb_data_req(sreq, req_size);
		break;

	case RPMB_CMD_GET_DEV_INFO:
		dev_info = (struct rpmb_dev_info *)rsp;
		res = rpmb_get_dev_info(sreq, req_size, dev_info, rsp_size);
		break;

	default:
		EMSG("Unsupported RPMB command: %d", sreq->cmd);
		res = TEEC_ERROR_BAD_PARAMETERS;
		break;
	}

	return res;
}
