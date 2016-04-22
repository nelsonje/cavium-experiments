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


static const size_t shared_packet_size = 233;
CVMX_SHARED uint64_t shared_packet[] = {
  0xffffffffffff0003ULL,
  0xba12de3d08004500ULL,
  0x00d7244d40000111ULL,
  0xb1acc0a810cdc0a8ULL,
  0x10ff008a008a00c3ULL,
  0x9322110a10fcc0a8ULL,
  0x10cd008a00bb0000ULL,
  0x2046484546464446ULL,
  0x4543414341434143ULL,
  0x4143414341434143ULL,
  0x4143414341434141ULL,
  0x4100204648455046ULL,
  0x43454c4548464345ULL,
  0x5046464641434143ULL,
  0x4143414341434143ULL,
  0x41424f00ff534d42ULL,
  0x2500000000000000ULL,
  0x0000000000000000ULL,
  0x0000000000000000ULL,
  0x0000000011000013ULL,
  0x0000000000000000ULL,
  0x0000000000000000ULL,
  0x0000001300560003ULL,
  0x0001000100020024ULL,
  0x005c4d41494c534cULL,
  0x4f545c42524f5753ULL,
  0x45000801070f0114ULL,
  0x90a1b5bf00000000ULL,
  0x5745535400c41503ULL,
  0xfe00000000000000ULL };

static const size_t static_packet_size = 233;
static uint64_t static_packet[] = {
  0xffffffffffff0003ULL,
  0xba12de3d08004500ULL,
  0x00d7244d40000111ULL,
  0xb1acc0a810cdc0a8ULL,
  0x10ff008a008a00c3ULL,
  0x9322110a10fcc0a8ULL,
  0x10cd008a00bb0000ULL,
  0x2046484546464446ULL,
  0x4543414341434143ULL,
  0x4143414341434143ULL,
  0x4143414341434141ULL,
  0x4100204648455046ULL,
  0x43454c4548464345ULL,
  0x5046464641434143ULL,
  0x4143414341434143ULL,
  0x41424f00ff534d42ULL,
  0x2500000000000000ULL,
  0x0000000000000000ULL,
  0x0000000000000000ULL,
  0x0000000011000013ULL,
  0x0000000000000000ULL,
  0x0000000000000000ULL,
  0x0000001300560003ULL,
  0x0001000100020024ULL,
  0x005c4d41494c534cULL,
  0x4f545c42524f5753ULL,
  0x45000801070f0114ULL,
  0x90a1b5bf00000000ULL,
  0x5745535400c41503ULL,
  0xfe00000000000000ULL };




/**
 * Explore address translation modes by trying to send packets allocated in different ways.
 *
 */
void application_main_loop(void)
{
  uint64_t        port;
  cvmx_buf_ptr_t  packet_ptr;
  cvmx_pko_command_word0_t pko_command;
  int queue, ret;
  int pko_port = -1;
  int corenum = cvmx_get_core_num();

  const int use_ipd_no_wptr = octeon_has_feature(OCTEON_FEATURE_NO_WPTR);
  printf("NOTE: use_ipd_no_wptr = %d\n", use_ipd_no_wptr);

  //
  // Let's explore translating virtual addresses of various kinds to physical addresses!
  //
  // It turns out there are two functions to do this:
  //   cvmx_ptr_to_phys() just masks bits off the address
  //   cvmx_ptr_to_phys2() actually reads the TLB 
  // (look at cvmx-access-native.h in the SDK to see the code)
  //
    
  uint64_t array_on_stack[233] = {0};
  memcpy( &array_on_stack[0], &shared_packet[0], 233 );
  uint64_t * packet_stack = &array_on_stack[0]; 
  printf("core %2d:       stack: virtual %18p, physical %18p, physical2 %18p\n",
         corenum, packet_stack, (void*)cvmx_ptr_to_phys(packet_stack), (void*)cvmx_ptr_to_phys2(packet_stack) );
                                                                                                                                                                                  
  uint64_t * packet_malloc = malloc( 233 );  // TODO: should probably freed after being sent
  memcpy( packet_malloc, &shared_packet[0], 233 );
  printf("core %2d:      malloc: virtual %18p, physical %18p, physical2 %18p\n",
         corenum, packet_malloc, (void*)cvmx_ptr_to_phys(packet_malloc), (void*)cvmx_ptr_to_phys2(packet_malloc) );
                                                                                                                                                                                  
  uint64_t * packet_shared = &shared_packet[0];
  printf("core %2d: CVMX_SHARED: virtual %18p, physical %18p, physical2 %18p\n",
         corenum, packet_shared, (void*)cvmx_ptr_to_phys(packet_shared), (void*)cvmx_ptr_to_phys2(packet_shared) );
                                                                                                                                                                                  
  uint64_t * packet_static = &static_packet[0];
  printf("core %2d:      static: virtual %18p, physical %18p, physical2 %18p\n",
         corenum, packet_static, (void*)cvmx_ptr_to_phys(packet_static), (void*)cvmx_ptr_to_phys2(packet_static) );
                                                                                                                                                                                  
  uint64_t * packet_bootmem = cvmx_bootmem_alloc( 1 << 3, 128 );
  memcpy( packet_bootmem, &shared_packet[0], 233 );
  printf("core %2d:     bootmem: virtual %18p, physical %18p, physical2 %18p\n",
         corenum, packet_bootmem, (void*)cvmx_ptr_to_phys(packet_bootmem), (void*)cvmx_ptr_to_phys2(packet_bootmem) );

  // I tried this both with CVMX_USE_1_TO_1_TLB_MAPPINGS on and off,
  // in both 32- and 64-bit Simple Executive Standalone mode. I had
  // thought that turning this on would map everything so that all
  // virtual addresses were also physical addresses. This is not the
  // case; turning this on only makes addresses from
  // cvmx_bootmem_alloc() be equivalent.
    
  // Note that the docs say setting CVMX_USE_1_TO_1_TLB_MAPPINGS to
  // on is not recommended because it can lead to problems when
  // porting. I suspect it is really only intended for use in 32-bit
  // mode.

  // The key discovery here is that cvmx_ptr_to_phys2() is
  // definitely the function to use.

  //
  // now send packets
  //
    
  void * packets[] = { (void*) packet_stack,
                       (void*) packet_malloc,
                       (void*) packet_shared,
                       (void*) packet_static,
                       (void*) packet_bootmem };
  const int count = sizeof(packets) / sizeof(void*);
  const uint16_t packet_size = shared_packet_size;

  int i;
  for( i = 0; i < count; ++i )
    {
      // choose which verison to send
      void * packet = packets[i];
      
      // send all packets out a single port on the 68XX
      port = 2048;

      // compute correct output port
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
      
      //
      // Build a PKO command word for this packet
      //

      printf("NOTE: preparing to send packet %d on core %d of %d bytes from %p/%p\n",
             i, corenum, packet_size, packet, (void*)cvmx_ptr_to_phys2(packet) );

      // first, clear command word union.
      pko_command.u64 = 0;

      // ensure atomic access to the output port while sending the packet
      // note: if we had a work queue entry, we could do cvmx_pko_send_packet_prepare(port, queue, CVMX_PKO_LOCK_ATOMIC_TAG);
      cvmx_pko_send_packet_prepare(port, queue, CVMX_PKO_LOCK_CMD_QUEUE);
      
      printf("NOTE: done preparing to send packet %d on core %d\n", i, corenum);

      // if we're in the simulator, count that we're sending a packet
      if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
        {
          cvmx_fau_atomic_add64(FAU_PACKETS, 1);
          cvmx_fau_atomic_add64(FAU_OUTSTANDING, 1);
        }

      // if we're in the simulator, set the PKO command word to count
      // sent packets for termination detection
      if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
        {  // decrement register once packet is sent
          pko_command.s.size0 = CVMX_FAU_OP_SIZE_64;
          pko_command.s.subone0 = 1;
          pko_command.s.reg0 = FAU_OUTSTANDING;
        }

      // 
      // now build pointer to packet data
      //
      
      // first, clear packet_ptr union
      packet_ptr.u64 = 0;

      // now, fill in fields of packet_ptr
      packet_ptr.s.i = 0;    // this xor pko_command.s.dontfree determines whether this buffer will be freed.
      packet_ptr.s.back = 0; // unused here; can ignore.
      packet_ptr.s.pool = 0; // unused here, since we're not freeing (pool to free to when freeing)
      packet_ptr.s.size = packet_size; // #bytes when not pointing to a gather list, or #segs in gather list
      packet_ptr.s.addr = cvmx_ptr_to_phys2(packet); // physical byte pointer to packet data

      // record total packet size (of all segments) in PKO
      pko_command.s.total_bytes = packet_size;
      pko_command.s.segs = 1;     // only using a single segment here
      pko_command.s.dontfree = 1; // don't try to free buffers by default
      //pko_command.s.gather = 1; // pointer points to gather list, rather than linked list of buffers

      // shouldn't be using little-endian bitfields here.
#ifdef __LITTLE_ENDIAN_BITFIELD
      pko_command.s.le = 1;
#endif
      
      /* For SRIO interface, build the header and remove SRIO RX word 0 */
      if (octeon_has_feature(OCTEON_FEATURE_SRIO) && port >= 40 && port < 44)
        {
          if (cvmx_srio_omsg_desc(port, &packet_ptr, NULL) >= 0)
            pko_command.s.total_bytes -= 8;
        }

      /*
       * Send the packet and wait for the tag switch to complete before
       * accessing the output queue. This ensures the locking required
       * for the queue.
       *
       */
      printf("NOTE: finishing packet send %d on core %d\n", i, corenum);
      if (octeon_has_feature(OCTEON_FEATURE_PKND))
        ret = cvmx_pko_send_packet_finish_pkoid(pko_port, queue,
                                                pko_command, packet_ptr, CVMX_PKO_LOCK_CMD_QUEUE);
      else
        ret = cvmx_pko_send_packet_finish(port, queue, pko_command,
                                          packet_ptr, CVMX_PKO_LOCK_CMD_QUEUE);
      if (ret)
        {
          printf("Failed to send packet using cvmx_pko_send_packet_finish\n");
          cvmx_fau_atomic_add64(FAU_ERRORS, 1);
        }
    }
  printf("NOTE: done finishing packet send %d on core %d\n", i, corenum);
}





//
// What follows is essentially setup/teardown code.
//





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
 * Perform application specific shutdown
 *
 * @param num_processors
 *               The number of processors available.
 */
static void application_shutdown(int num_processors)
{
  uint64_t run_cycles = stop_cycle - start_cycle;
  float cycles_packet;

  /* Display a rough calculation for the cycles/packet. If you need
     accurate results, run lots of packets. */
  uint64_t count = cvmx_fau_fetch_and_add64(FAU_PACKETS, 0);
  cycles_packet = run_cycles / (float)count;
  printf("Total %lld packets in %lld cycles (%2.2f cycles/packet)\n",
         (unsigned long long)count, (unsigned long long)run_cycles, cycles_packet );

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

  if (IS_INIT_CORE) {
    cvmx_dprintf("Using config string \n");
    cvmx_set_app_config_str(app_config_str);
  }
    
  cvmx_user_app_init();

  /* compute coremask_passthrough on all cores for the first barrier sync below */
  sysinfo = cvmx_sysinfo_get();
  cvmx_coremask_copy(&coremask_passthrough, &sysinfo->core_mask);

  // guess at total number of packets (based on old code; not relevant here)
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
