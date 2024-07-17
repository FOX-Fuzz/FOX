/*
   american fuzzy lop++ - forkserver header
   ----------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code that implements a forkserver. This is used by the fuzzer
   as well the other components like afl-tmin.

 */

#ifndef __AFL_FORKSERVER_H
#define __AFL_FORKSERVER_H

#include <stdio.h>
#include <stdbool.h>

#include "types.h"

#ifdef __linux__
/**
 * Nyx related typedefs taken from libnyx.h
 */

typedef enum NyxReturnValue {

  Normal,
  Crash,
  Asan,
  Timeout,
  InvalidWriteToPayload,
  Error,
  IoError,
  Abort,

} NyxReturnValue;

typedef enum NyxProcessRole {

  StandAlone,
  Parent,
  Child,

} NyxProcessRole;

typedef struct {

  void *(*nyx_config_load)(const char *sharedir);
  void (*nyx_config_set_workdir_path)(void *config, const char *workdir);
  void (*nyx_config_set_input_buffer_size)(void    *config,
                                           uint32_t input_buffer_size);
  void (*nyx_config_set_input_buffer_write_protection)(
      void *config, bool input_buffer_write_protection);
  void (*nyx_config_set_hprintf_fd)(void *config, int32_t hprintf_fd);
  void (*nyx_config_set_process_role)(void *config, enum NyxProcessRole role);
  void (*nyx_config_set_reuse_snapshot_path)(void       *config,
                                             const char *reuse_snapshot_path);

  void *(*nyx_new)(void *config, uint32_t worker_id);
  void (*nyx_shutdown)(void *qemu_process);
  void (*nyx_option_set_reload_mode)(void *qemu_process, bool enable);
  void (*nyx_option_set_timeout)(void *qemu_process, uint8_t timeout_sec,
                                 uint32_t timeout_usec);
  void (*nyx_option_apply)(void *qemu_process);
  void (*nyx_set_afl_input)(void *qemu_process, uint8_t *buffer, uint32_t size);
  enum NyxReturnValue (*nyx_exec)(void *qemu_process);
  uint8_t *(*nyx_get_bitmap_buffer)(void *qemu_process);
  size_t (*nyx_get_bitmap_buffer_size)(void *qemu_process);
  uint32_t (*nyx_get_aux_string)(void *nyx_process, uint8_t *buffer,
                                 uint32_t size);

  bool (*nyx_remove_work_dir)(const char *workdir);
  bool (*nyx_config_set_aux_buffer_size)(void    *config,
                                         uint32_t aux_buffer_size);

} nyx_plugin_handler_t;

/* Imports helper functions to enable Nyx mode (Linux only )*/
nyx_plugin_handler_t *afl_load_libnyx_plugin(u8 *libnyx_binary);

#endif

#define WINNING_CAPACITY 5120
#define FOX_BR_CANDIDATE_CAPACITY 5120
#define FOX_MUTANT_BUF_CAPACITY 10240

typedef struct afl_forkserver {

  /* a program that includes afl-forkserver needs to define these */

  /* FOX-specific members */
  u8 *trace_bits;                       /* SHM with instrumentation bitmap  */
  u32 *winning_list;                    /* List of line search winners      */
  u32 winning_cnt;                      /* Count of line search winners     */
  u32 winner_cnt;                       /* Count of line search winners for display stats */
  u32 winning_capacity;                 /* Capacity of line search winners  */
  u8 skip_classify_count;               /* Skip classify count              */
  u8 br_trace_setting;                  /* Branch trace setting             */
  u32 *br_inc_winner;                   /* Branch increment winner array    */
  u32 *br_dec_winner;                   /* Branch decrement winner array    */
  u8 **mutant_buf;                      /* Array of mutant buffers          */
  u32 *mutant_len;                      /* Array of mutant lengths          */
  u32 mutant_ref_cnt;                   /* Reference count of the mutant    */
  u32 *br_inc_id;                       /* Branch increment id array        */
  u32 *br_inc_dist_id;                  /* Branch increment distance id array */
  u32 br_inc_cnt;                       /* Branch increment array count     */
  u32 *br_dec_id;                       /* Branch decrement id array        */
  u32 *br_dec_dist_id;                  /* Branch decrement distance id array */
  u32 br_dec_cnt;                       /* Branch decrement array count     */
  u32 *handler_candidate_id;            /* Handler candidate id array       */
  u32 *handler_candidate_dist_id;       /* Handler candidate distance id array */
  u32 handler_candidate_cnt;            /* Handler candidate array count    */
  u8 *fallthrough_line_search;          /* Whether this branch should default to line search */
  u8 *size_gradient_checked;            /* Size gradient checked            */
  s64 *br_inc;                          /* Branch increment array           */
  s64 *br_dec;                          /* Branch decrement array           */
  float *subgrad_inc;                   /* Subgradient increment array      */
  float *subgrad_dec;                   /* Subgradient decrement array      */
  s64 *local_br_bits;                   /* Local branch bits                */
  u8 *local_bits;                       /* Local bits                       */
  s64 *br_bits;                         /* Branch bits                      */
  u8 *br_cov;                           /* Branch coverage instrumentation is active */
  u8 *br_hit;                           /* Branch hit instrumentation array */
  u8 *br_dist_id;                       /* Branch distance id array         */
  u8 *cmp_type;                         /* Comparison type array            */
  u64 *spent_time_us;                   /* Spent time in us                 */
  u64 *productive_time_us;              /* Productive time in us            */
  u32 *added_seeds;                     /* Added seeds                      */
  s64 *global_br_bits;                  /* Global branch bits               */
  u32 fox_br_candidate_capacity;        /* Fox branch candidate capacity    */
  u32 fox_mutant_buf_capacity;          /* Fox mutant buffer capacity       */
  u32 *border_edge_parent;              /* Border edge parent               */
  u32 *border_edge_child;               /* Border edge child                */
  u32 *border_edge_2_br_dist;           /* Border edge to branch distance   */
  u32 *border_edge_2_str_len;           /* Border edge to string length     */
  struct queue_entry ***border_edge_seed_list; /* Border edge to seed list  */
  u32 *border_edge_seed_list_cnt;       /* Border edge to seed list count   */
  u32 *border_edge_seed_list_capacity;  /* Border edge to seed list capacity*/
  u32 *border_edge_parent_first_id;     /* Border edge parent first id      */
  u32 *num_of_children;                 /* Number of children               */
  FILE *wd_scheduler_log_file;          /* WD scheduler log file            */
#ifdef FOX_INTROSPECTION
  FILE *fox_debug_log_file;             /* FOX debug log file               */
  u64 *reached_before_step;             /* Reached before Newton step       */
  u64 *reached_after_step;              /* Reached after Newton step        */
  u64 *midpoint_convex_before_step;     /* Midpoint convex before Newton step */
  u64 *midpoint_convex_after_step;      /* Midpoint convex after Newton step */
#endif

  s32 fsrv_pid,                         /* PID of the fork server           */
      child_pid,                        /* PID of the fuzzed program        */
      child_status,                     /* waitpid result for the child     */
      out_dir_fd;                       /* FD of the lock file              */

  s32 out_fd,                           /* Persistent fd for fsrv->out_file */
      dev_urandom_fd,                   /* Persistent fd for /dev/urandom   */

      dev_null_fd,                      /* Persistent fd for /dev/null      */
      fsrv_ctl_fd,                      /* Fork server control pipe (write) */
      fsrv_st_fd;                       /* Fork server status pipe (read)   */

  u32 exec_tmout;                       /* Configurable exec timeout (ms)   */
  u32 init_tmout;                       /* Configurable init timeout (ms)   */
  u32 map_size;                         /* map size used by the target      */
  u32 real_map_size;                    /* real map size, unaligned         */
  u32 snapshot;                         /* is snapshot feature used         */
  u64 mem_limit;                        /* Memory cap for child (MB)        */

  u64 total_execs;                      /* How often run_target was called  */

  u8 *out_file,                         /* File to fuzz, if any             */
      *target_path;                     /* Path of the target               */

  FILE *plot_file;                      /* Gnuplot output file              */

  /* Note: last_run_timed_out is u32 to send it to the child as 4 byte array */
  u32 last_run_timed_out;               /* Traced process timed out?        */

  u8 last_kill_signal;                  /* Signal that killed the child     */

  bool use_shmem_fuzz;                  /* use shared mem for test cases    */

  bool support_shmem_fuzz;              /* set by afl-fuzz                  */

  bool use_fauxsrv;                     /* Fauxsrv for non-forking targets? */

  bool qemu_mode;                       /* if running in qemu mode or not   */

  bool frida_mode;                     /* if running in frida mode or not   */

  bool frida_asan;                    /* if running with asan in frida mode */

  bool cs_mode;                      /* if running in CoreSight mode or not */

  bool use_stdin;                       /* use stdin for sending data       */

  bool no_unlink;                       /* do not unlink cur_input          */

  bool uses_asan;                       /* Target uses ASAN?                */

  bool debug;                           /* debug mode?                      */

  bool uses_crash_exitcode;             /* Custom crash exitcode specified? */
  u8   crash_exitcode;                  /* The crash exitcode specified     */

  u32 *shmem_fuzz_len;                  /* length of the fuzzing test case  */

  u8 *shmem_fuzz;                       /* allocated memory for fuzzing     */

  char *cmplog_binary;                  /* the name of the cmplog binary    */

  /* persistent mode replay functionality */
  u32 persistent_record;                /* persistent replay setting        */
#ifdef AFL_PERSISTENT_RECORD
  u32  persistent_record_idx;           /* persistent replay cache ptr      */
  u32  persistent_record_cnt;           /* persistent replay counter        */
  u8  *persistent_record_dir;
  u8 **persistent_record_data;
  u32 *persistent_record_len;
  s32  persistent_record_pid;
#endif

  /* Function to kick off the forkserver child */
  void (*init_child_func)(struct afl_forkserver *fsrv, char **argv);

  u8 *afl_ptr;                          /* for autodictionary: afl ptr      */

  void (*add_extra_func)(void *afl_ptr, u8 *mem, u32 len);

  u8 child_kill_signal;
  u8 fsrv_kill_signal;

  u8 persistent_mode;

#ifdef __linux__
  nyx_plugin_handler_t *nyx_handlers;
  char                 *out_dir_path;    /* path to the output directory     */
  u8                    nyx_mode;        /* if running in nyx mode or not    */
  bool                  nyx_parent;      /* create initial snapshot          */
  bool                  nyx_standalone;  /* don't serialize the snapshot     */
  void                 *nyx_runner;      /* nyx runner object                */
  u32                   nyx_id;          /* nyx runner id (0 -> master)      */
  u32                   nyx_bind_cpu_id; /* nyx runner cpu id                */
  char                 *nyx_aux_string;
  u32                   nyx_aux_string_len;
  bool                  nyx_use_tmp_workdir;
  char                 *nyx_tmp_workdir_path;
  s32                   nyx_log_fd;
#endif

} afl_forkserver_t;

typedef enum fsrv_run_result {

  /* 00 */ FSRV_RUN_OK = 0,
  /* 01 */ FSRV_RUN_TMOUT,
  /* 02 */ FSRV_RUN_CRASH,
  /* 03 */ FSRV_RUN_ERROR,
  /* 04 */ FSRV_RUN_NOINST,
  /* 05 */ FSRV_RUN_NOBITS,

} fsrv_run_result_t;

void afl_fsrv_init(afl_forkserver_t *fsrv);
void afl_fsrv_init_dup(afl_forkserver_t *fsrv_to, afl_forkserver_t *from);
void afl_fsrv_start(afl_forkserver_t *fsrv, char **argv,
                    volatile u8 *stop_soon_p, u8 debug_child_output);
u32  afl_fsrv_get_mapsize(afl_forkserver_t *fsrv, char **argv,
                          volatile u8 *stop_soon_p, u8 debug_child_output);
void afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv, u8 *buf, size_t len);
fsrv_run_result_t afl_fsrv_run_target(afl_forkserver_t *fsrv, u32 timeout,
                                      volatile u8 *stop_soon_p);
void              afl_fsrv_killall(void);
void              afl_fsrv_deinit(afl_forkserver_t *fsrv);
void              afl_fsrv_kill(afl_forkserver_t *fsrv);

#ifdef __APPLE__
  #define MSG_FORK_ON_APPLE                                                    \
    "    - On MacOS X, the semantics of fork() syscalls are non-standard and " \
    "may\n"                                                                    \
    "      break afl-fuzz performance optimizations when running "             \
    "platform-specific\n"                                                      \
    "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"
#else
  #define MSG_FORK_ON_APPLE ""
#endif

#ifdef RLIMIT_AS
  #define MSG_ULIMIT_USAGE "      ( ulimit -Sv $[%llu << 10];"
#else
  #define MSG_ULIMIT_USAGE "      ( ulimit -Sd $[%llu << 10];"
#endif                                                        /* ^RLIMIT_AS */

#endif

