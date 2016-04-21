/***********************license start***************
 * Copyright (c) 2003-2010  Cavium Inc. (support@cavium.com). All rights
 * reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.

 *   * Neither the name of Cavium Inc. nor the names of
 *     its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.

 * This Software, including technical data, may be subject to U.S. export  control
 * laws, including the U.S. Export Administration Act and its  associated
 * regulations, and may be subject to export or import  regulations in other
 * countries.

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR
 * WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO
 * THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY REPRESENTATION OR
 * DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,
 * MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF
 * VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR
 * PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 ***********************license end**************************************/


/*
 * File version info: $Id: passthrough.c 87283 2013-08-23 18:13:43Z lrosenboim $
 *
 */

#include <stdio.h>
#include <string.h>

#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-spinlock.h"
#include "cvmx-fpa.h"
#include "cvmx-ilk.h"
#include "cvmx-pip.h"
#include "cvmx-ipd.h"
#include "cvmx-pko.h"
#include "cvmx-dfa.h"
#include "cvmx-pow.h"
#include "cvmx-sysinfo.h"
#include "cvmx-coremask.h"
#include "cvmx-bootmem.h"
#include "cvmx-helper.h"
#include "cvmx-app-hotplug.h"
#include "cvmx-helper-cfg.h"
#include "cvmx-srio.h"
#include "cvmx-config-parse.h"


#define FAU_PACKETS     ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 0))   /**< Fetch and add for counting packets processed */
#define FAU_ERRORS      ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 8))   /**< Fetch and add for counting detected errors */
#define FAU_OUTSTANDING ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 16))  /**< Fetch and add for counting outstanding packets */

static CVMX_SHARED uint64_t start_cycle;
static CVMX_SHARED uint64_t stop_cycle;
static unsigned int packet_termination_num;

static int volatile core_unplug_requested  = 0;
static int volatile app_shutdown_requested = 0;

#include "app.config"

/* Note: The dump_packet routine that used to be here has been moved to
    cvmx_helper_dump_packet. */
//#define DUMP_PACKETS 1
//#define DUMP_STATS
//#define SWAP_MAC_ADDR

#ifdef SWAP_MAC_ADDR
static inline void
swap_mac_addr(uint64_t pkt_ptr)
{
    uint16_t s;
    uint32_t w;

    /* assuming an IP/IPV6 pkt i.e. L2 header is 2 byte aligned, 4 byte non-aligned */
    s = *(uint16_t*)pkt_ptr;
    w = *(uint32_t*)(pkt_ptr+2);
    *(uint16_t*)pkt_ptr = *(uint16_t*)(pkt_ptr+6);
    *(uint32_t*)(pkt_ptr+2) = *(uint32_t*)(pkt_ptr+8);
    *(uint16_t*)(pkt_ptr+6) = s;
    *(uint32_t*)(pkt_ptr+8) = w;
}
#endif







/**
 * Process incoming packets. Just send them back out the
 * same interface.
 *
 */
void application_main_loop(void)
{
    cvmx_wqe_t *    work;
    uint64_t        port;
    cvmx_buf_ptr_t  packet_ptr;
    cvmx_pko_command_word0_t pko_command;
    const int use_ipd_no_wptr = octeon_has_feature(OCTEON_FEATURE_NO_WPTR);
    int queue, ret, pko_port, corenum;
    int packet_pool = (int)cvmx_fpa_get_packet_pool();
    int wqe_pool = (int)cvmx_fpa_get_wqe_pool();
    int packet_pool_size = cvmx_fpa_get_packet_pool_block_size();
    int wqe_pool_size = cvmx_fpa_get_wqe_pool_block_size();

    pko_port = -1;
    corenum = cvmx_get_core_num();

    /* Build a PKO pointer to this packet */
    pko_command.u64 = 0;
    if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
    {
       pko_command.s.size0 = CVMX_FAU_OP_SIZE_64;
       pko_command.s.subone0 = 1;
       pko_command.s.reg0 = FAU_OUTSTANDING;
    }

    while (1)
    {

        /* get the next packet/work to process from the POW unit. */
        if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
        {
           work = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
           if (work == NULL) {
               if (cvmx_fau_fetch_and_add64(FAU_PACKETS, 0) == packet_termination_num)
                   break;
               continue;
           }
        }
        else
        {
           work = cvmx_pow_work_request_sync(CVMX_POW_WAIT);
           if (work == NULL) {
               continue;
           }
        }


        port = cvmx_wqe_get_port(work);

        /* Interlaken - fix port number */
        if (((port & 0xffe) == 0x480) || ((port & 0xffe) == 0x580))
            port &= ~0x80;

        /* Check for errored packets, and drop.  If sender does not respond
        ** to backpressure or backpressure is not sent, packets may be truncated if
        ** the GMX fifo overflows */
        if (cvmx_unlikely(work->word2.snoip.rcv_error))
        {
            /* Work has error, so drop */
            cvmx_helper_free_packet_data(work);
            if (use_ipd_no_wptr)
		    cvmx_fpa_free(work, packet_pool, 0);
            else
		    cvmx_fpa_free(work, wqe_pool, 0);
            continue;
        }

        /*
         * Insert packet processing here.
         *
         * Define DUMP_PACKETS to dump packets to the console.
         * Note that due to multiple cores executing in parallel, the output
         * will likely be interleaved.
         *
         */
        #ifdef DUMP_PACKETS
        printf("Processing packet\n");
        cvmx_helper_dump_packet(work);
        #endif

#ifdef DUMP_STATS
        printf ("port to send out: %lu\n", port);
        cvmx_helper_show_stats(port);
#endif


        /*
         * Begin packet output by requesting a tag switch to atomic.
         * Writing to a packet output queue must be synchronized across cores.
         */
	if (octeon_has_feature(OCTEON_FEATURE_PKND))
	{
	    /* PKO internal port is different than IPD port */
	    pko_port = cvmx_helper_cfg_ipd2pko_port_base(port);
	    queue = cvmx_pko_get_base_queue_pkoid(pko_port);
	    queue += (corenum % cvmx_pko_get_num_queues_pkoid(pko_port));
	}
	else
	{
	    queue = cvmx_pko_get_base_queue(port);
	    queue += (corenum % cvmx_pko_get_num_queues(port));
	}
        cvmx_pko_send_packet_prepare(port, queue, CVMX_PKO_LOCK_ATOMIC_TAG);

        if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
        {
           /* Increment the total packet counts */
           cvmx_fau_atomic_add64(FAU_PACKETS, 1);
           cvmx_fau_atomic_add64(FAU_OUTSTANDING, 1);
        }

        #ifdef SWAP_MAC_ADDR
        int is_ip = !work->word2.s.not_IP;
        #endif

        /* Build a PKO pointer to this packet */
        if (work->word2.s.bufs == 0)
        {
            /* Packet is entirely in the WQE. Give the WQE to PKO and have it
                free it */
            pko_command.s.total_bytes = cvmx_wqe_get_len(work);
            pko_command.s.segs = 1;
            packet_ptr.u64 = 0;
            if (use_ipd_no_wptr)
            {
		packet_ptr.s.pool = packet_pool;
		packet_ptr.s.size = packet_pool_size;
            }
            else
            {
		packet_ptr.s.pool = wqe_pool;
		packet_ptr.s.size = wqe_pool_size;
            }
            packet_ptr.s.addr = cvmx_ptr_to_phys(work->packet_data);
            if (cvmx_likely(!work->word2.s.not_IP))
            {
                /* The beginning of the packet moves for IP packets */
                if (work->word2.s.is_v6)
                    packet_ptr.s.addr += 2;
                else
                    packet_ptr.s.addr += 6;
            }
        }
        else
        {
            pko_command.s.total_bytes = cvmx_wqe_get_len(work);
            pko_command.s.segs = work->word2.s.bufs;
            packet_ptr = work->packet_ptr;
            if (!use_ipd_no_wptr)
                cvmx_fpa_free(work, wqe_pool, 0);
        }
#ifdef __LITTLE_ENDIAN_BITFIELD
        pko_command.s.le = 1;
#endif
        /* For SRIO interface, build the header and remove SRIO RX word 0 */
        if (octeon_has_feature(OCTEON_FEATURE_SRIO) && port >= 40 && port < 44)
        {
            if (cvmx_srio_omsg_desc(port, &packet_ptr, NULL) >= 0)
                pko_command.s.total_bytes -= 8;
        }

        #ifdef SWAP_MAC_ADDR
        if (is_ip)
            swap_mac_addr((uint64_t)cvmx_phys_to_ptr((uint64_t)packet_ptr.s.addr));
        #endif

        /*
         * Send the packet and wait for the tag switch to complete before
         * accessing the output queue. This ensures the locking required
         * for the queue.
         *
         */
	if (octeon_has_feature(OCTEON_FEATURE_PKND))
	    ret = cvmx_pko_send_packet_finish_pkoid(pko_port, queue,
	        pko_command, packet_ptr, CVMX_PKO_LOCK_ATOMIC_TAG);
	else
	    ret = cvmx_pko_send_packet_finish(port, queue, pko_command,
	        packet_ptr, CVMX_PKO_LOCK_ATOMIC_TAG);
        if (ret)
        {
            printf("Failed to send packet using cvmx_pko_send_packet_finish\n");
            cvmx_fau_atomic_add64(FAU_ERRORS, 1);
        }
    }
}













/**
 * Setup the Cavium Simple Executive Libraries using defaults
 *
 * @param num_packet_buffers
 *               Number of outstanding packets to support
 * @return Zero on success
 */
static int application_init_simple_exec(int num_packet_buffers)
{
    int result;

    if (cvmx_helper_initialize_fpa(num_packet_buffers, num_packet_buffers, CVMX_PKO_MAX_OUTPUT_QUEUES * 4, 0, 0))
        return -1;

    if (cvmx_helper_initialize_sso(num_packet_buffers))
        return -1;


    if (octeon_has_feature(OCTEON_FEATURE_NO_WPTR))
    {
        cvmx_ipd_ctl_status_t ipd_ctl_status;
        printf("Enabling CVMX_IPD_CTL_STATUS[NO_WPTR]\n");
        ipd_ctl_status.u64 = cvmx_read_csr(CVMX_IPD_CTL_STATUS);
        ipd_ctl_status.s.no_wptr = 1;
#ifdef __LITTLE_ENDIAN_BITFIELD
        ipd_ctl_status.s.pkt_lend = 1;
        ipd_ctl_status.s.wqe_lend = 1;
#endif
        cvmx_write_csr(CVMX_IPD_CTL_STATUS, ipd_ctl_status.u64);
    }

    cvmx_helper_cfg_opt_set(CVMX_HELPER_CFG_OPT_USE_DWB, 0);
    result = cvmx_helper_initialize_packet_io_global();

    /* Don't enable RED on simulator */
    if (cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM)
        cvmx_helper_setup_red(num_packet_buffers/4, num_packet_buffers/8);

    /* Leave 16 bytes space for the ethernet header */
    cvmx_write_csr(CVMX_PIP_IP_OFFSET, 2);
    cvmx_helper_cfg_set_jabber_and_frame_max();
    cvmx_helper_cfg_store_short_packets_in_wqe();

    /* Initialize the FAU registers. */
    cvmx_fau_atomic_write64(FAU_ERRORS, 0);
    if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
    {
        cvmx_fau_atomic_write64(FAU_PACKETS, 0);
        cvmx_fau_atomic_write64(FAU_OUTSTANDING, 0);
    }

    return result;
}

/**
 * Clean up and properly shutdown the simple exec libraries.
 *
 * @return Zero on success. Non zero means some resources are
 *         unaccounted for. In this case error messages will have
 *         been displayed during shutdown.
 */
static int application_shutdown_simple_exec(void)
{
    int result = 0;
    int status;
    int pool;

    cvmx_helper_shutdown_packet_io_global();

    for (pool=0; pool<CVMX_FPA_NUM_POOLS; pool++)
    {
        if (cvmx_fpa_get_block_size(pool) > 0)
        {
            status = cvmx_fpa_shutdown_pool(pool);
            result |= status;
        }
    }

    return result;
}

/**
 * Determine if a number is approximately equal to a match
 * value. Checks if the supplied value is within 5% of the
 * expected value.
 *
 * @param value    Value to check
 * @param expected Value needs to be within 5% of this value.
 * @return Non zero if the value is out of range.
 */
static int cycle_out_of_range(float value, float expected)
{
    uint64_t range = expected / 5; /* 5% */
    if (range<1)
        range = 1;

    return ((value < expected - range) || (value > expected + range));
}


/**
 * Perform application specific shutdown
 *
 * @param num_processors
 *               The number of processors available.
 */
static void application_shutdown(int num_processors)
{
    uint64_t run_cycles = stop_cycle - start_cycle;
    float cycles_packet;

    /* The following speed checks assume you are using the original test data
        and executing with debug turned off. */
    const float * expected_cycles;
    const float cn68xx_cycles[32] = {350.0, 175.0, 130.0, 92.0, 90.0, 85.0, 80.0, 65.0, 65.0, 65.0, 65.0, 65.0 , 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0, 65.0};
    const float cn6xxx_cycles[10] = {350.0, 175.0, 130.0, 92.0, 90.0, 85.0, 80.0, 65.0, 65.0, 65.0};
    const float cn50xx_cycles[2] = {282.0, 156.0};
    const float cn3xxx_cycles[16] = {244.0, 123.0, 90.0, 63.0, 55.0, 47.0, 42.0, 39.0, 38.0, 38.0, 38.0, 38.0, 38.0, 38.0, 38.0, 38.0};
    const float cn3020_cycles[2] = {272.0, 150.0};
    const float cn3010_cycles[1] = {272.0};
    const float cn3005_cycles[1] = {315.0};

    if (OCTEON_IS_MODEL(OCTEON_CN3005))
        expected_cycles = cn3005_cycles;
    else if (OCTEON_IS_MODEL(OCTEON_CN3020))
        expected_cycles = cn3020_cycles;
    else if (OCTEON_IS_MODEL(OCTEON_CN30XX))
        expected_cycles = cn3010_cycles;
    else if (OCTEON_IS_MODEL(OCTEON_CN50XX))
        expected_cycles = cn50xx_cycles;
    else if (OCTEON_IS_MODEL(OCTEON_CN68XX))
        expected_cycles = cn68xx_cycles;
    else if (OCTEON_IS_OCTEON2() || OCTEON_IS_MODEL(OCTEON_CN70XX))
        expected_cycles = cn6xxx_cycles;
    else
        expected_cycles = cn3xxx_cycles;

    /* Display a rough calculation for the cycles/packet. If you need
        accurate results, run lots of packets. */
    uint64_t count = cvmx_fau_fetch_and_add64(FAU_PACKETS, 0);
    cycles_packet = run_cycles / (float)count;
    printf("Total %lld packets in %lld cycles (%2.2f cycles/packet)[expected %2.2f cycles/packet]\n",
           (unsigned long long)count, (unsigned long long)run_cycles, cycles_packet, expected_cycles[num_processors-1]);

    if (cycle_out_of_range(cycles_packet, expected_cycles[num_processors-1]))
        printf("Cycles-per-packet is larger than the expected!\n");

    /* Display the results if a failure was detected. */
    if (cvmx_fau_fetch_and_add64(FAU_ERRORS, 0))
        printf("Errors detected. TEST FAILED\n");

    /* Wait for PKO to complete */
    printf("Waiting for packet output to finish\n");
    while (cvmx_fau_fetch_and_add64(FAU_OUTSTANDING, 0) != 0)
    {
        /* Spinning again */
    }

    /* Delay so the last few packets make it out. The fetch and add
        is a little ahead of the hardware */
    cvmx_wait(1000000);
}

/**
 * Main entry point
 *
 * @return exit code
 */
int main(int argc, char *argv[])
{
    cvmx_sysinfo_t *sysinfo;
    struct cvmx_coremask coremask_passthrough;
    int result = 0;

#define IS_INIT_CORE	(cvmx_is_init_core())

#ifdef ENABLE_USING_CONFIG_STRING
    if (IS_INIT_CORE) {
	    cvmx_dprintf("Using config string \n");
	    cvmx_set_app_config_str(app_config_str);
    }
#endif
    
    cvmx_user_app_init();

    /* compute coremask_passthrough on all cores for the first barrier sync below */
    sysinfo = cvmx_sysinfo_get();
    cvmx_coremask_copy(&coremask_passthrough, &sysinfo->core_mask);

    if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
    {
        if (OCTEON_IS_MODEL(OCTEON_CN3005) || OCTEON_IS_MODEL(OCTEON_CNF71XX))
            packet_termination_num = 3032;
        else if (OCTEON_IS_MODEL(OCTEON_CN31XX) || OCTEON_IS_MODEL(OCTEON_CN3010) || OCTEON_IS_MODEL(OCTEON_CN50XX))
            packet_termination_num = 4548;
        else if (OCTEON_IS_MODEL(OCTEON_CN70XX))
            packet_termination_num = 1516;
        else
//#define SINGLE_PORT_SIM
#ifdef SINGLE_PORT_SIM
            packet_termination_num = 1516;
#else
            packet_termination_num = 6064;
#endif
    }
    else
       packet_termination_num = 1000;

    /*
     * elect a core to perform boot initializations, as only one core needs to
     * perform this function.
     *
     */

    if (IS_INIT_CORE) {
        printf("Version: %s\n", cvmx_helper_get_version());

        if (octeon_has_feature(OCTEON_FEATURE_SRIO))
        {
            if (cvmx_helper_interface_get_mode(4) == CVMX_HELPER_INTERFACE_MODE_SRIO)
                cvmx_srio_initialize(0, 0);
            if (cvmx_helper_interface_get_mode(5) == CVMX_HELPER_INTERFACE_MODE_SRIO)
                cvmx_srio_initialize(1, 0);
        }

        /* 64 is the minimum number of buffers that are allocated to receive
           packets, but the real hardware, allocate above this minimal number. */
        if ((result = application_init_simple_exec(packet_termination_num+80)) != 0) {
            printf("Simple Executive initialization failed.\n");
            printf("TEST FAILED\n");
            return result;
        }
    }

    cvmx_coremask_barrier_sync(&coremask_passthrough);

    cvmx_helper_initialize_packet_io_local();

    /* Remember when we started the test.  For accurate numbers it needs to be as
       close as possible to the running of the application main loop. */
    if (IS_INIT_CORE) {
        if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
        {
            printf("Waiting to give packet input (~1Gbps) time to read the packets...\n");
            if (OCTEON_IS_MODEL(OCTEON_CN68XX))
            {
                cvmx_sso_iq_com_cnt_t sso_iq_com_cnt;
                do
                {
                    sso_iq_com_cnt.u64 = cvmx_read_csr(CVMX_SSO_IQ_COM_CNT);
#ifdef DUMP_STATS
                    printf("sso_iq_com_cnt.u64 = %lu\n", sso_iq_com_cnt.u64);
#endif
                } while (sso_iq_com_cnt.s.iq_cnt < packet_termination_num);
            }
            else
            {
                cvmx_pow_iq_com_cnt_t pow_iq_com_cnt;
                do
                {
                    pow_iq_com_cnt.u64 = cvmx_read_csr(CVMX_POW_IQ_COM_CNT);
                } while (pow_iq_com_cnt.s.iq_cnt < packet_termination_num);
            }
            printf("Done waiting\n");
        }

        start_cycle = cvmx_get_cycle();
    }

    cvmx_coremask_barrier_sync(&coremask_passthrough);

    // now actually do work
    application_main_loop();

    cvmx_coremask_barrier_sync(&coremask_passthrough);

    /* Remember when we stopped the test. This could have been done in the
       application_shutdown, but for accurate numbers it needs to be as close as
       possible to the running of the application main loop. */
    if (cvmx_is_init_core())
        stop_cycle = cvmx_get_cycle();

    cvmx_coremask_barrier_sync(&coremask_passthrough);

#if CVMX_PKO_USE_FAU_FOR_OUTPUT_QUEUES
    /* Free the prefetched output queue buffer if allocated */
    {
        void * buf_ptr = cvmx_phys_to_ptr(cvmx_scratch_read64(CVMX_SCR_OQ_BUF_PRE_ALLOC));
        if (buf_ptr)
		cvmx_fpa_free(buf_ptr, cvmx_fpa_get_pko_pool(), 0);
    }
#endif

    /* use core 0 to perform application shutdown as well. */
    if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM &&
        cvmx_is_init_core())
    {

        int num_processors;
	num_processors = cvmx_coremask_get_core_count(&coremask_passthrough);
        application_shutdown(num_processors);

        if ((result = application_shutdown_simple_exec()) != 0) {
            printf("Simple Executive shutdown failed.\n");
            printf("TEST FAILED\n");
        }
    }

    cvmx_coremask_barrier_sync(&coremask_passthrough);

    return result;
}
