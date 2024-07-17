/*
   american fuzzy lop++ - bitmap related routines
   ----------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <limits.h>
#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

void write_bitmap(afl_state_t *afl) {

  u8  fname[PATH_MAX];
  s32 fd;

  if (!afl->bitmap_changed) { return; }
  afl->bitmap_changed = 0;

  snprintf(fname, PATH_MAX, "%s/fuzz_bitmap", afl->out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  ck_write(fd, afl->virgin_bits, afl->fsrv.map_size, fname);

  close(fd);

}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

u32 count_bits(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (likely(v == 0xffffffff)) {

      ret += 32;
      continue;

    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

u32 count_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (likely(!v)) { continue; }
    if (v & 0x000000ffU) { ++ret; }
    if (v & 0x0000ff00U) { ++ret; }
    if (v & 0x00ff0000U) { ++ret; }
    if (v & 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

u32 count_non_255_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (likely(v == 0xffffffffU)) { continue; }
    if ((v & 0x000000ffU) != 0x000000ffU) { ++ret; }
    if ((v & 0x0000ff00U) != 0x0000ff00U) { ++ret; }
    if ((v & 0x00ff0000U) != 0x00ff0000U) { ++ret; }
    if ((v & 0xff000000U) != 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */
const u8 simplify_lookup[256] = {

    [0] = 1, [1 ... 255] = 128

};

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

const u8 count_class_lookup8[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

};

u16 count_class_lookup16[65536];

void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {

    for (b2 = 0; b2 < 256; b2++) {

      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];

    }

  }

}

static inline s64 icmp_single_br_dist_le(s16 *br_dist_buf, s16 sw_len, bool *has_overflown) {
  s64 total = 0;
  s64 order = 1;
  for (s16 i = 0; i < sw_len; i++) {
    // Check for overflow
    // total += br_dist_buf[i] * order;
    if (unlikely(__builtin_add_overflow(total, br_dist_buf[i] * order, &total))) {
      *has_overflown = true;
      return -1;
    }
    order <<= 8;
  }
  return total;
}

 void increment_hit_bits(afl_state_t *afl) {

  u64 *cur_trace_bit_batch = (u64 *)afl->fsrv.trace_bits;
  u32 map_size_batched = (afl->fsrv.real_map_size + 7) >> 3;
  u32 winning_cnt = 0;
  u32 *num_of_children = afl->fsrv.num_of_children;
  u32 *border_edge_parent_first_id = afl->fsrv.border_edge_parent_first_id;
  u32 *border_edge_2_br_dist = afl->fsrv.border_edge_2_br_dist;
  u32 *border_edge_2_str_len = afl->fsrv.border_edge_2_str_len;
  u32 *border_edge_child = afl->fsrv.border_edge_child;
  u8 *virgin_bits = afl->virgin_bits;
  u8 *trace_bits = afl->fsrv.trace_bits;
  s64 *global_br_bits = afl->fsrv.global_br_bits;
  s64 *br_bits = afl->fsrv.br_bits;
  u8 *br_cov = afl->fsrv.br_cov;
  u32 *winning_list = afl->fsrv.winning_list;
  u32 *br_inc_winner = afl->fsrv.br_inc_winner;
  u32 *br_dec_winner = afl->fsrv.br_dec_winner;
  u8 *cmp_type = afl->fsrv.cmp_type;
  s64 *local_br_bits = afl->fsrv.local_br_bits;
  u8 *local_bits = afl->fsrv.local_bits;
  u32 cur_mutant_id = afl->stage_cur;
  u32 cur_num_diff = afl->num_diff;
  s64 *br_inc = afl->fsrv.br_inc;
  s64 *br_dec = afl->fsrv.br_dec;
  u32 br_inc_cnt = afl->fsrv.br_inc_cnt;
  u32 br_dec_cnt = afl->fsrv.br_dec_cnt;
  u32 *br_inc_id = afl->fsrv.br_inc_id;
  u32 *br_inc_dist_id = afl->fsrv.br_inc_dist_id;
  u32 *br_dec_id = afl->fsrv.br_dec_id;
  u32 *br_dec_dist_id = afl->fsrv.br_dec_dist_id;
  u32 *mutant_ref_cnt = &(afl->fsrv.mutant_ref_cnt);
  float *subgrad_inc = afl->fsrv.subgrad_inc;
  float *subgrad_dec = afl->fsrv.subgrad_dec;
  u8 br_trace_setting = afl->fsrv.br_trace_setting;
  u64 *spent_time_us = afl->fsrv.spent_time_us;
  u64 *productive_time_us = afl->fsrv.productive_time_us;
  struct queue_entry **wd_scheduler_top_rated = afl->wd_scheduler_top_rated;
  s64 diff_l1_norm = afl->diff_l1_norm;
  u32 *handler_candidate_id = afl->fsrv.handler_candidate_id;
  u32 *handler_candidate_dist_id = afl->fsrv.handler_candidate_dist_id;
  u32 handler_candidate_cnt = afl->fsrv.handler_candidate_cnt;
  u8 *fallthrough_line_search = afl->fsrv.fallthrough_line_search;
  u8* size_gradient_checked = afl->fsrv.size_gradient_checked;
  u32 *added_seeds = afl->fsrv.added_seeds;
  struct queue_entry *queue_cur = afl->queue_cur;
  u64 this_exec_us = queue_cur ? queue_cur->exec_us : 1;
  u32 fox_br_candidate_capacity = afl->fsrv.fox_br_candidate_capacity;
  u32 winning_capacity = afl->fsrv.winning_capacity;
  u32 max_added_seeds = afl->max_added_seeds;
  u8 shared_mode = afl->wd_scheduler_shared_mode;
  u8 handler_candidate_ok = cur_num_diff < MAX_HANDLER_NUM_DIFF;
  u8 handler_candidate_icmp_ok = queue_cur && shared_mode ? this_exec_us * cur_num_diff < MAX_HANDLER_EXEC_TIME_US : 1;
  u8 not_dry_run = !afl->wd_scheduler_dry_run;
  u8 line_search = afl->line_search;

  // Flag to check if the existing mutant decrease the global branch
  // distance for at least one branch while staying with estimated size boudns
  bool has_decreased_global_br = false;
  bool has_overflown = false;

  // AS: Check a sparse array faster by batching eight u8 ptrs as one u64 ptr.
  for (u32 i = 0; i < map_size_batched; i++) {
    if (likely(!cur_trace_bit_batch[i]))
      continue;

    u8 *cur_trace_bit = (u8 *)(cur_trace_bit_batch + i);

    for (u32 j = 0; j < 8; j++) {
      if (!cur_trace_bit[j])
        continue;

      u32 parent = i * 8 + j;

      u32 cur_num_of_children = num_of_children[parent];
      u8 cmp_type_parent = cmp_type[parent];
      spent_time_us[parent] += this_exec_us;

      // AS: only check conditional and arithmetic branches
      if (cur_num_of_children < 2 || cmp_type_parent == NOT_INSTRUMENTED) {
        continue;
      }

      u32 base_border_edge_id = border_edge_parent_first_id[parent];

      // Handler branch case:
      u8 branch_flip = 0;
      u8 default_line_search_fallthrough = 0;

      u8 handler = is_handler(cmp_type_parent);
      u8 fallthrough = can_fallthrough_handler(cmp_type_parent, shared_mode);

      if (fallthrough && !handler_candidate_icmp_ok) {
        handler = 0;
        default_line_search_fallthrough = 1;
      }

      if (handler) {
        for (u32 cur_border_edge_id = base_border_edge_id; cur_border_edge_id < base_border_edge_id + cur_num_of_children; cur_border_edge_id++) {
          u32 child_node = border_edge_child[cur_border_edge_id];
          u32 base_br_dist_edge_id = border_edge_2_br_dist[cur_border_edge_id];

          if (br_cov[base_br_dist_edge_id])
            continue;

          if (!is_reached(child_node, virgin_bits, trace_bits)) {
            if (++branch_flip == 2)
              br_cov[base_br_dist_edge_id] = 1;
            continue;
          }

          if (fallthrough_line_search[base_br_dist_edge_id]) {
            default_line_search_fallthrough = 1;
            continue;
          }

          u32 const_len = border_edge_2_str_len[cur_border_edge_id];

          // array to store seed's branch distance
          s16 *this_local_br_bits = (s16 *)(local_br_bits + base_br_dist_edge_id);
          // array to store current' mutant's branch distance
          s16 *this_br_bits = (s16 *)(br_bits + base_br_dist_edge_id);

          u8 has_var_len = cmp_type_parent == STRCMP || cmp_type_parent == STRNCMP || cmp_type_parent == STRSTR;

          // current mutant's var length
          s16 mutant_var_len = has_var_len ? this_br_bits[const_len]: (s16) const_len;

          s64 total_br_dist_abs = 0;
          if (fallthrough) {
            has_overflown = false;
            total_br_dist_abs = llabs(icmp_single_br_dist_le(this_br_bits, const_len, &has_overflown));
            if (has_overflown) {
                continue;
            }
          } else {
            // number of matched bytes, large is better
            for (u32 i = 0; i < const_len; i++)
              total_br_dist_abs += (!this_br_bits[i]);
          }

          // first time hit
          if (!wd_scheduler_top_rated[cur_border_edge_id]) {
            productive_time_us[cur_border_edge_id] += this_exec_us;
            added_seeds[cur_border_edge_id]++;
            global_br_bits[base_br_dist_edge_id] = total_br_dist_abs;
            if (unlikely(winning_cnt >= winning_capacity)) { PFATAL("BUG: number of winners exceeds capacity"); }
            winning_list[winning_cnt] = cur_border_edge_id;
            winning_cnt++;
            has_decreased_global_br = true;
            continue;
          }

          // a large number is better
          if (total_br_dist_abs > global_br_bits[base_br_dist_edge_id] && added_seeds[cur_border_edge_id] < max_added_seeds) {
            if (likely(not_dry_run))
              added_seeds[cur_border_edge_id]++;
            productive_time_us[cur_border_edge_id] += this_exec_us;
            global_br_bits[base_br_dist_edge_id] = total_br_dist_abs;
            if (unlikely(winning_cnt >= winning_capacity)) { PFATAL("BUG: number of winners exceeds capacity"); }
            winning_list[winning_cnt] = cur_border_edge_id;
            winning_cnt++;
            has_decreased_global_br = true;
          }

          // if tracing seed input, save seed's (local) branch distance
          if (br_trace_setting == BR_TRACE_SEED_INPUT) {
            if (fallthrough)
              local_bits[cur_border_edge_id] = 2; // fallthrough need update local_bits
            else
              local_bits[cur_border_edge_id] = 1;
            for (u32 i = 0; i < const_len; i++)
              this_local_br_bits[i] = this_br_bits[i];
            if (has_var_len)
              this_local_br_bits[const_len] = mutant_var_len;
          }

          // AS: only compute when tracing local search mutations and when the mutant hits the same horizon branch as the seed and when the mutant differs from the seed
          if (!(line_search && br_trace_setting == BR_TRACE_LOCAL_SEARCH && local_bits[cur_border_edge_id] && cur_num_diff && handler_candidate_ok))
            continue;

          s16 seed_var_len = has_var_len ? this_local_br_bits[const_len] : (s16) const_len;
          // FLAG: promsing mutant must have at least one byte diff
          s64 br_diff = 0;
          u32 min_len = (u32) s16_min3(seed_var_len, mutant_var_len, (s16) const_len);
          for (u32 i = 0; i < min_len; i++)
            br_diff += (this_br_bits[i] != this_local_br_bits[i]);

          if (!br_diff)
            continue;

          if (unlikely(handler_candidate_cnt >= fox_br_candidate_capacity)) { PFATAL("BUG: number of handler candidates exceeds capacity"); }
          handler_candidate_id[handler_candidate_cnt] = cur_border_edge_id;
          handler_candidate_dist_id[handler_candidate_cnt++] = base_br_dist_edge_id;
          br_inc_winner[base_br_dist_edge_id] = cur_mutant_id;
          (*mutant_ref_cnt)++;
        }

        if (!default_line_search_fallthrough)
          continue;
      }

      // binary branch case:
      branch_flip = 0;
      for (u32 cur_border_edge_id = base_border_edge_id; cur_border_edge_id < base_border_edge_id + cur_num_of_children; cur_border_edge_id++) {
        u32 child_node = border_edge_child[cur_border_edge_id];
        u32 br_dist_edge_id = border_edge_2_br_dist[cur_border_edge_id];

        if (br_cov[br_dist_edge_id])
          continue;

        if (!is_reached(child_node, virgin_bits, trace_bits)) {
          if (++branch_flip == 2)
            br_cov[br_dist_edge_id] = 1;
          continue;
        }

        s64 br_dist = 0;
        if (fallthrough) {
          u32 sw_len = border_edge_2_str_len[cur_border_edge_id];
          s16 *this_br_bits = (s16 *)(br_bits + br_dist_edge_id);
          has_overflown = false;
          br_dist = icmp_single_br_dist_le(this_br_bits, sw_len, &has_overflown);
          if (has_overflown)
              continue;
        } else {
          br_dist = br_bits[br_dist_edge_id];
        }

        // AS: if tracing seed input, save seed's (local) branch distance
        if (br_trace_setting == BR_TRACE_SEED_INPUT) {
          local_bits[cur_border_edge_id] = 1;
          local_br_bits[br_dist_edge_id] = br_dist;
        }

        s64 br_dist_abs = llabs(br_dist);

        // first time hit
        if (!wd_scheduler_top_rated[cur_border_edge_id]) {
          productive_time_us[cur_border_edge_id] += this_exec_us;
          added_seeds[cur_border_edge_id]++;
          global_br_bits[br_dist_edge_id] = br_dist_abs;
          if (unlikely(winning_cnt >= winning_capacity)) { PFATAL("BUG: number of winners exceeds capacity"); }
          winning_list[winning_cnt] = cur_border_edge_id;
          winning_cnt++;
          has_decreased_global_br = true;
          continue;
        }

        s64 global_br_dist_abs = global_br_bits[br_dist_edge_id];

        if (handler && global_br_dist_abs == 0)
          continue;

        if (br_dist_abs < global_br_dist_abs && added_seeds[cur_border_edge_id] < max_added_seeds) {

          // Calculate gradient with respect to size
          u32 size_seed = wd_scheduler_top_rated[cur_border_edge_id]->len;
          u32 size_mut = afl->mut_len;
          if (!has_decreased_global_br && size_mut > size_seed) {

            if (size_gradient_checked[br_dist_edge_id])
              continue;

            s64 num = (br_dist_abs - global_br_dist_abs); // y2 - y1
            s64 size_diff = (s64) size_mut - (s64) size_seed; // x2 - x1
            double grad_size = ((double)num / (double)size_diff); // m
            double intercept = br_dist_abs - ((grad_size) * ((double)size_mut)); // c
            double expected_size = - (intercept / grad_size); // x
            if (expected_size > MAX_STEP_FILE) {
                size_gradient_checked[br_dist_edge_id] = 1;
#ifdef FOX_INTROSPECTION
	            fprintf(afl->fsrv.fox_debug_log_file, "Skipping Cmp type:%d Num:%ld Size mut:%d Size seed:%d Grad:%f Intercept:%f Step_needed:%f Br_new:%ld Br_old:%ld\n", cmp_type_parent, num, size_mut, size_seed, grad_size, intercept, expected_size, br_dist_abs, global_br_dist_abs);
#endif
	            continue;
            }
          }
          has_decreased_global_br = true;
          productive_time_us[cur_border_edge_id] += this_exec_us;
          if (likely(not_dry_run))
            added_seeds[cur_border_edge_id]++;
          global_br_bits[br_dist_edge_id] = br_dist_abs;
          if (unlikely(winning_cnt >= winning_capacity)) { PFATAL("BUG: number of winners exceeds capacity"); }
          winning_list[winning_cnt] = cur_border_edge_id;
          winning_cnt++;
        }

        // AS: only compute when tracing local search mutations and when the mutant hits the same horizon branch as the seed and when the mutant differs from the seed
        if (!(line_search && br_trace_setting == BR_TRACE_LOCAL_SEARCH && local_bits[cur_border_edge_id] && cur_num_diff))
          continue;

        if (unlikely(local_bits[cur_border_edge_id] == 2)) { // fallthrough need update local bits
          u32 sw_len = border_edge_2_str_len[cur_border_edge_id];
          has_overflown = false;
          local_br_bits[br_dist_edge_id] = icmp_single_br_dist_le((s16 *)(local_br_bits + br_dist_edge_id), sw_len, &has_overflown);
          if (has_overflown)
              continue;
          local_bits[cur_border_edge_id] = 1;
        }
        s64 local_br_dist = local_br_bits[br_dist_edge_id];
        s64 br_diff = br_dist - local_br_dist;
        float cur_subgrad = ((float)br_diff) / ((float)diff_l1_norm);

        if (!br_diff)
          continue;

        if (br_diff > 0) {
          u8 first_time_inc = !br_inc[br_dist_edge_id];

          if (first_time_inc) {
            if (unlikely(br_inc_cnt >= fox_br_candidate_capacity)) { PFATAL("BUG: number of br inc candidates exceeds capacity"); }
            br_inc_id[br_inc_cnt] = cur_border_edge_id;
            br_inc_dist_id[br_inc_cnt] = br_dist_edge_id;
            br_inc_cnt++;
          }

          if (first_time_inc || cur_subgrad > subgrad_inc[cur_border_edge_id]) {
            (*mutant_ref_cnt)++;
            br_inc[br_dist_edge_id] = br_diff;
            br_inc_winner[br_dist_edge_id] = cur_mutant_id;
            subgrad_inc[cur_border_edge_id] = cur_subgrad;
          }
        } else {
          u8 first_time_dec = !br_dec[br_dist_edge_id];

          if (first_time_dec) {
            if (unlikely(br_dec_cnt >= fox_br_candidate_capacity)) { PFATAL("BUG: number of br inc candidates exceeds capacity"); }
            br_dec_id[br_dec_cnt] = cur_border_edge_id;
            br_dec_dist_id[br_dec_cnt] = br_dist_edge_id;
            br_dec_cnt++;
          }

          if (first_time_dec || cur_subgrad < subgrad_dec[cur_border_edge_id]) {
            (*mutant_ref_cnt)++;
            br_dec[br_dist_edge_id] = br_diff;
            br_dec_winner[br_dist_edge_id] = cur_mutant_id;
            subgrad_dec[cur_border_edge_id] = cur_subgrad;
          }
        }
      }
    }
  }

  afl->fsrv.winning_cnt = winning_cnt;
  afl->fsrv.winner_cnt += winning_cnt;
  afl->fsrv.br_inc_cnt = br_inc_cnt;
  afl->fsrv.br_dec_cnt = br_dec_cnt;
  afl->fsrv.handler_candidate_cnt = handler_candidate_cnt;
}

inline void increment_hit_bits_timeout(afl_state_t *afl) {

  u64 *cur_trace_bit_batch = (u64 *)afl->fsrv.trace_bits;
  u32 map_size_batched = (afl->fsrv.real_map_size + 7) >> 3;
  u64 this_exec_us = afl->queue_cur ? afl->queue_cur->exec_us : 1;

  // AS: Check a sparse array faster by batching eight u8 ptrs as one u64 ptr.
  for (u32 i = 0; i < map_size_batched; i++) {
    if (likely(!cur_trace_bit_batch[i]))
      continue;

    u8 *cur_trace_bit = (u8 *)(cur_trace_bit_batch + i);

    for (u32 j = 0; j < 8; j++) {
      if (!cur_trace_bit[j])
        continue;

      u32 parent = i * 8 + j;
      afl->fsrv.spent_time_us[parent] += this_exec_us;
    }
  }
}

/* Import coverage processing routines. */

#ifdef WORD_SIZE_64
  #include "coverage-64.h"
#else
  #include "coverage-32.h"
#endif

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

inline u8 has_new_bits(afl_state_t *afl, u8 *virgin_map) {

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)afl->fsrv.trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 7) >> 3);

#else

  u32 *current = (u32 *)afl->fsrv.trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 3) >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

  u8 ret = 0;
  while (i--) {

    if (unlikely(*current)) discover_word(&ret, current, virgin);

    current++;
    virgin++;

  }

  if (unlikely(ret) && likely(virgin_map == afl->virgin_bits))
    afl->bitmap_changed = 1;

  return ret;

}

/* A combination of classify_counts and has_new_bits. If 0 is returned, then the
 * trace bits are kept as-is. Otherwise, the trace bits are overwritten with
 * classified values.
 *
 * This accelerates the processing: in most cases, no interesting behavior
 * happen, and the trace bits will be discarded soon. This function optimizes
 * for such cases: one-pass scan on trace bits without modifying anything. Only
 * on rare cases it fall backs to the slow path: classify_counts() first, then
 * return has_new_bits(). */

inline u8 has_new_bits_unclassified(afl_state_t *afl, u8 *virgin_map) {
  afl->fsrv.skip_classify_count = 1;

  /* Handle the hot path first: no new coverage */
  u8 *end = afl->fsrv.trace_bits + afl->fsrv.map_size;

#ifdef WORD_SIZE_64

  if (!skim((u64 *)virgin_map, (u64 *)afl->fsrv.trace_bits, (u64 *)end))
    return 0;

#else

  if (!skim((u32 *)virgin_map, (u32 *)afl->fsrv.trace_bits, (u32 *)end))
    return 0;

#endif                                                     /* ^WORD_SIZE_64 */
  classify_counts(&afl->fsrv);
  afl->fsrv.skip_classify_count = 0;
  return has_new_bits(afl, virgin_map);

}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  u32 i = 0;

  while (i < afl->fsrv.map_size) {

    if (*(src++)) { dst[i >> 3] |= 1 << (i & 7); }
    ++i;

  }

}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Returns a ptr to afl->describe_op_buf_256. */

u8 *describe_op(afl_state_t *afl, u8 new_bits, size_t max_description_len) {

  u8 is_timeout = 0;

  if (new_bits & 0xf0) {

    new_bits -= 0x80;
    is_timeout = 1;

  }

  size_t real_max_len =
      MIN(max_description_len, sizeof(afl->describe_op_buf_256));
  u8 *ret = afl->describe_op_buf_256;

  if (unlikely(afl->syncing_party)) {

    sprintf(ret, "sync:%s,src:%06u", afl->syncing_party, afl->syncing_case);

  } else {

    sprintf(ret, "src:%06u", afl->current_entry);

    if (afl->splicing_with >= 0) {

      sprintf(ret + strlen(ret), "+%06d", afl->splicing_with);

    }

    sprintf(ret + strlen(ret), ",time:%llu,execs:%llu",
            get_cur_time() + afl->prev_run_time - afl->start_time,
            afl->fsrv.total_execs);

    if (afl->current_custom_fuzz &&
        afl->current_custom_fuzz->afl_custom_describe) {

      /* We are currently in a custom mutator that supports afl_custom_describe,
       * use it! */

      size_t len_current = strlen(ret);
      ret[len_current++] = ',';
      ret[len_current] = '\0';

      ssize_t size_left = real_max_len - len_current - strlen(",+cov") - 2;
      if (is_timeout) { size_left -= strlen(",+tout"); }
      if (unlikely(size_left <= 0)) FATAL("filename got too long");

      const char *custom_description =
          afl->current_custom_fuzz->afl_custom_describe(
              afl->current_custom_fuzz->data, size_left);
      if (!custom_description || !custom_description[0]) {

        DEBUGF("Error getting a description from afl_custom_describe");
        /* Take the stage name as description fallback */
        sprintf(ret + len_current, "op:%s", afl->stage_short);

      } else {

        /* We got a proper custom description, use it */
        strncat(ret + len_current, custom_description, size_left);

      }

    } else {

      /* Normal testcase descriptions start here */
      sprintf(ret + strlen(ret), ",op:%s", afl->stage_short);

      if (afl->stage_cur_byte >= 0) {

        sprintf(ret + strlen(ret), ",pos:%d", afl->stage_cur_byte);

        if (afl->stage_val_type != STAGE_VAL_NONE) {

          sprintf(ret + strlen(ret), ",val:%s%+d",
                  (afl->stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                  afl->stage_cur_val);

        }

      } else {

        sprintf(ret + strlen(ret), ",rep:%d", afl->stage_cur_val);

      }

    }

  }

  if (is_timeout) { strcat(ret, ",+tout"); }

  if (new_bits == 2) { strcat(ret, ",+cov"); }

  if (unlikely(strlen(ret) >= max_description_len))
    FATAL("describe string is too long");

  return ret;

}

#endif                                                     /* !SIMPLE_FILES */

/* Write a message accompanying the crash directory :-) */

void write_crash_readme(afl_state_t *afl) {

  u8    fn[PATH_MAX];
  s32   fd;
  FILE *f;

  u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

  sprintf(fn, "%s/crashes/README.txt", afl->out_dir);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  /* Do not die on errors here - that would be impolite. */

  if (unlikely(fd < 0)) { return; }

  f = fdopen(fd, "w");

  if (unlikely(!f)) {

    close(fd);
    return;

  }

  fprintf(
      f,
      "Command line used to find this crash:\n\n"

      "%s\n\n"

      "If you can't reproduce a bug outside of afl-fuzz, be sure to set the "
      "same\n"
      "memory limit. The limit used for this fuzzing session was %s.\n\n"

      "Need a tool to minimize test cases before investigating the crashes or "
      "sending\n"
      "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

      "Found any cool bugs in open-source tools using afl-fuzz? If yes, please "
      "post\n"
      "to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the "
      "issues\n"
      " are fixed :)\n\n",

      afl->orig_cmdline,
      stringify_mem_size(val_buf, sizeof(val_buf),
                         afl->fsrv.mem_limit << 20));      /* ignore errors */

  fclose(f);

}

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

u8 __attribute__((hot))
save_if_interesting(afl_state_t *afl, void *mem, u32 len, u8 fault) {

  if (unlikely(len == 0)) { return 0; }
  afl->mut_len = len;

  if (unlikely(fault == FSRV_RUN_TMOUT && afl->afl_env.afl_ignore_timeouts)) {

    if (likely(afl->schedule >= FAST && afl->schedule <= RARE)) {

      classify_counts(&afl->fsrv);
      u64 cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      // Saturated increment
      if (likely(afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF))
        afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

    }

    return 0;

  }

  u8  fn[PATH_MAX];
  u8 *queue_fn = "";
  u8  new_bits = 0, keeping = 0, res, classified = 0, is_timeout = 0,
     need_hash = 1;
  s32 fd;
  u64 cksum = 0;

  /* Update path frequency. */

  /* Generating a hash on every input is super expensive. Bad idea and should
     only be used for special schedules */
  if (likely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    classify_counts(&afl->fsrv);
    classified = 1;
    need_hash = 0;

    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    /* Saturated increment */
    if (likely(afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF))
      afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

  }

  if (likely(fault == afl->crash_mode)) {
    if (likely(afl->schedule == WD_SCHEDULER))
      increment_hit_bits(afl);

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    if (likely(classified)) {

      new_bits = has_new_bits(afl, afl->virgin_bits);

    } else {

      new_bits = has_new_bits_unclassified(afl, afl->virgin_bits);

    if (likely(afl->schedule == WD_SCHEDULER)) {
      if (!new_bits && afl->fsrv.winning_cnt) {
        if (afl->fsrv.skip_classify_count) {
          classify_counts(&afl->fsrv);
          has_new_bits(afl, afl->virgin_bits);
        }
        new_bits = 1;
        afl->queued_val_items++;
      }
    }

      if (unlikely(new_bits)) { classified = 1; }

    }

    if (likely(!new_bits)) {

      if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
      return 0;

    }

  save_to_queue:
    if (new_bits == 2)
      afl->queued_new_items++;

#ifndef SIMPLE_FILES

    queue_fn =
        alloc_printf("%s/queue/id:%06u,%s", afl->out_dir, afl->queued_items,
                     describe_op(afl, new_bits + is_timeout,
                                 NAME_MAX - strlen("id:000000,")));

#else

    queue_fn =
        alloc_printf("%s/queue/id_%06u", afl->out_dir, afl->queued_items);

#endif                                                    /* ^!SIMPLE_FILES */
    fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
    ck_write(fd, mem, len, queue_fn);
    close(fd);
    add_to_queue(afl, queue_fn, len, 0);

    if (unlikely(afl->fuzz_mode) &&
        likely(afl->switch_fuzz_mode && !afl->non_instrumented_mode)) {

      if (afl->afl_env.afl_no_ui) {

        ACTF("New coverage found, switching back to exploration mode.");

      }

      afl->fuzz_mode = 0;

    }

#ifdef INTROSPECTION
    if (afl->custom_mutators_count && afl->current_custom_fuzz) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

          const char *ptr = el->afl_custom_introspection(el->data);

          if (ptr != NULL && *ptr != 0) {

            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);

          }

        }

      });

    } else if (afl->mutation[0] != 0) {

      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);

    }

#endif

    if (new_bits == 2) {

      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;

    }

    if (unlikely(need_hash && new_bits)) {

      /* due to classify counts we have to recalculate the checksum */
      afl->queue_top->exec_cksum =
          hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
      need_hash = 0;

    }

    /* For AFLFast schedules we update the new queue entry */
    if (likely(cksum)) {

      afl->queue_top->n_fuzz_entry = cksum % N_FUZZ_SIZE;
      afl->n_fuzz[afl->queue_top->n_fuzz_entry] = 1;

    }

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */
    res = calibrate_case(afl, afl->queue_top, mem, afl->queue_cycle - 1, 0);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (likely(afl->q_testcase_max_cache_size)) {

      queue_testcase_store_mem(afl, afl->queue_top, mem);

    }

    keeping = 1;

    if (likely(afl->schedule == WD_SCHEDULER)) {
      u32 winning_cnt = afl->fsrv.winning_cnt;
      u32 *winning_list = afl->fsrv.winning_list;
      struct queue_entry *q = afl->queue_top;
      struct queue_entry **wd_scheduler_top_rated = afl->wd_scheduler_top_rated;
      for (u32 i = 0; i < winning_cnt; i++) {
        u32 border_edge_id = winning_list[i];
        wd_scheduler_top_rated[border_edge_id] = q;
      }
    }
  }

  if (likely(afl->schedule == WD_SCHEDULER) && fault)
    has_new_bits(afl, afl->virgin_bits);

  switch (fault) {

    case FSRV_RUN_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "non-instrumented"
         mode, we just keep everything. */

      ++afl->total_tmouts;
      if (likely(afl->schedule == WD_SCHEDULER))
        increment_hit_bits_timeout(afl);

      if (afl->saved_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (unlikely(!classified)) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_tmout)) { return keeping; }

      }

      is_timeout = 0x80;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file,
                      "UNIQUE_TIMEOUT CUSTOM %s = %s\n", ptr,
                      afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_TIMEOUT %s\n", afl->mutation);

      }

#endif

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (afl->fsrv.exec_tmout < afl->hang_tmout) {

        u8  new_fault;
        u32 tmp_len = write_to_testcase(afl, &mem, len, 0);

        if (likely(tmp_len)) {

          len = tmp_len;

        } else {

          len = write_to_testcase(afl, &mem, len, 1);

        }

        new_fault = fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);
        classify_counts(&afl->fsrv);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!afl->stop_soon && new_fault == FSRV_RUN_CRASH) {

          goto keep_as_crash;

        }

        if (afl->stop_soon || new_fault != FSRV_RUN_TMOUT) {

          if (afl->afl_env.afl_keep_timeouts) {

            ++afl->saved_tmouts;
            goto save_to_queue;

          } else {

            return keeping;

          }

        }

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s", afl->out_dir,
               afl->saved_hangs,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,")));

#else

      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu", afl->out_dir,
               afl->saved_hangs);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_hangs;

      afl->last_hang_time = get_cur_time();

      break;

    case FSRV_RUN_CRASH:

    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (likely(afl->schedule == WD_SCHEDULER))
          increment_hit_bits_timeout(afl);

        if (unlikely(!classified)) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_crash)) { return keeping; }

      }

      if (unlikely(!afl->saved_crashes) &&
          (afl->afl_env.afl_no_crash_readme != 1)) {

        write_crash_readme(afl);

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));

#else

      snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_crashes;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
                      ptr, afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

      }

#endif
      if (unlikely(afl->infoexec)) {

        // if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
        // we dont care if system errors, but we dont want a
        // compiler warning either
        // See
        // https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
        (void)(system(afl->infoexec) + 1);
#else
        WARNF("command execution unsupported");
#endif

      }

      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;

      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
  ck_write(fd, mem, len, fn);
  close(fd);

#ifdef __linux__
  if (afl->fsrv.nyx_mode && fault == FSRV_RUN_CRASH) {

    u8 fn_log[PATH_MAX];

    (void)(snprintf(fn_log, PATH_MAX, "%s.log", fn) + 1);
    fd = open(fn_log, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn_log); }

    u32 nyx_aux_string_len = afl->fsrv.nyx_handlers->nyx_get_aux_string(
        afl->fsrv.nyx_runner, afl->fsrv.nyx_aux_string,
        afl->fsrv.nyx_aux_string_len);

    ck_write(fd, afl->fsrv.nyx_aux_string, nyx_aux_string_len, fn_log);
    close(fd);

  }

#endif

  return keeping;

}

