/*
   american fuzzy lop++ - queue relates routines
   ---------------------------------------------

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
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <float.h>

#ifdef _STANDALONE_MODULE
void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  return;

}

void run_afl_custom_queue_new_entry(afl_state_t *afl, struct queue_entry *q,
                                    u8 *a, u8 *b) {

  return;

}

#endif

/* select next queue entry based on alias algo - fast! */

inline u32 select_next_queue_entry(afl_state_t *afl) {

  u32    s = rand_below(afl, afl->queued_items);
  double p = rand_next_percent(afl);

  /*
  fprintf(stderr, "select: p=%f s=%u ... p < prob[s]=%f ? s=%u : alias[%u]=%u"
  " ==> %u\n", p, s, afl->alias_probability[s], s, s, afl->alias_table[s], p <
  afl->alias_probability[s] ? s : afl->alias_table[s]);
  */

  return (p < afl->alias_probability[s] ? s : afl->alias_table[s]);

}

inline u32 select_next_queue_entry_wd_scheduler(afl_state_t *afl) {
  u32 border_edge_idx = afl->wd_scheduler_selected_border_edge_idx;
  u32 seed_idx = afl->wd_scheduler_top_rated[border_edge_idx]->id;

  afl->queue_buf[seed_idx]->perf_score = calculate_score_wd_scheduler(afl, afl->queue_buf[seed_idx]);

  return seed_idx;
}

double compute_weight(afl_state_t *afl, struct queue_entry *q,
                      double avg_exec_us, double avg_bitmap_size,
                      double avg_top_size) {

  double weight = 1.0;

  if (likely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    u32 hits = afl->n_fuzz[q->n_fuzz_entry];
    if (likely(hits)) { weight /= (log10(hits) + 1); }

  }

  if (likely(afl->schedule < RARE)) { weight *= (avg_exec_us / q->exec_us); }
  weight *= (log(q->bitmap_size) / avg_bitmap_size);
  weight *= (1 + (q->tc_ref / avg_top_size));

  if (unlikely(weight < 0.1)) { weight = 0.1; }
  if (unlikely(q->favored)) { weight *= 5; }
  if (unlikely(!q->was_fuzzed)) { weight *= 2; }
  if (unlikely(q->fs_redundant)) { weight *= 0.8; }

  return weight;

}

double calculate_score_wd_scheduler(afl_state_t *afl, struct queue_entry *q) {

  double perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  // TODO BUG FIXME: is this really a good idea?
  // This sounds like looking for lost keys under a street light just because
  // the light is better there.
  // Longer execution time means longer work on the input, the deeper in
  // coverage, the better the fuzzing, right? -mh

  u64 avg_exec_us = afl->wd_scheduler_avg_us;

  if (q->exec_us * 0.1 > avg_exec_us) {

    perf_score = 10;

  } else if (q->exec_us * 0.25 > avg_exec_us) {

    perf_score = 25;

  } else if (q->exec_us * 0.5 > avg_exec_us) {

    perf_score = 50;

  } else if (q->exec_us * 0.75 > avg_exec_us) {

    perf_score = 75;

  } else if (q->exec_us * 4 < avg_exec_us) {

    perf_score = 300;

  } else if (q->exec_us * 3 < avg_exec_us) {

    perf_score = 200;

  } else if (q->exec_us * 2 < avg_exec_us) {

    perf_score = 150;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > afl->wd_scheduler_havoc_max_mult * 100.0) {

    perf_score = afl->wd_scheduler_havoc_max_mult * 100.0;

  }

  return perf_score;

}

#ifdef FOX_INTROSPECTION
  void save_convexity_info(afl_state_t *afl) {
    int fd;
    u8 *tmp;
    FILE *f;
    u64 *reached_before_step = afl->fsrv.reached_before_step;
    u64 *midpoint_convex_before_step = afl->fsrv.midpoint_convex_before_step;
    u64 *reached_after_step = afl->fsrv.reached_after_step;
    u64 *midpoint_convex_after_step = afl->fsrv.midpoint_convex_after_step;
    u32 fox_map_size = afl->fox_map_size;

    tmp = alloc_printf("%s/reached_before_step", afl->out_dir);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
    ck_free(tmp);

    f = fdopen(fd, "w");
    if (!f) { PFATAL("fdopen() failed"); }

    for (u32 i = 0; i < fox_map_size; i++)
      fprintf(f, "%llu\n", reached_before_step[i]);

    fflush(f);
    fclose(f);

    tmp = alloc_printf("%s/midpoint_convex_before_step", afl->out_dir);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
    ck_free(tmp);

    f = fdopen(fd, "w");
    if (!f) { PFATAL("fdopen() failed"); }

    for (u32 i = 0; i < fox_map_size; i++)
      fprintf(f, "%llu\n", midpoint_convex_before_step[i]);

    fflush(f);
    fclose(f);

    tmp = alloc_printf("%s/reached_after_step", afl->out_dir);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
    ck_free(tmp);

    f = fdopen(fd, "w");
    if (!f) { PFATAL("fdopen() failed"); }

    for (u32 i = 0; i < fox_map_size; i++)
      fprintf(f, "%llu\n", reached_after_step[i]);

    fflush(f);
    fclose(f);

    tmp = alloc_printf("%s/midpoint_convex_after_step", afl->out_dir);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
    ck_free(tmp);

    f = fdopen(fd, "w");
    if (!f) { PFATAL("fdopen() failed"); }

    for (u32 i = 0; i < fox_map_size; i++)
      fprintf(f, "%llu\n", midpoint_convex_after_step[i]);

    fflush(f);
    fclose(f);
  }
#endif

static inline struct queue_entry *get_least_scheduled_seed(struct queue_entry **seed_list, u32 len) {
  u64 min_exec_us = UINT64_MAX;
  struct queue_entry *min_seed = NULL;
  for (u32 i = 0; i < len; i++) {
    struct queue_entry *seed = seed_list[i];
    u64 exec_us = (u64) ((1 + seed->schedule_cnt) * seed->exec_us);
    if (!seed->disabled && exec_us < min_exec_us) {
      min_exec_us = exec_us;
      min_seed = seed;
    }
  }
  return min_seed;
}

static inline struct queue_entry *top_rated_seed(afl_state_t *afl, u32 cur_border_edge_id, u32 parent) {
  if (afl->fsrv.cmp_type[parent] == NOT_INSTRUMENTED)
    return get_least_scheduled_seed(
        afl->fsrv.border_edge_seed_list[cur_border_edge_id],
        afl->fsrv.border_edge_seed_list_cnt[cur_border_edge_id]);
  return afl->wd_scheduler_top_rated[cur_border_edge_id];
}

void create_alias_table_wd_scheduler(afl_state_t *afl) {

  u64 *cur_virgin_bit_batch = (u64 *)afl->virgin_bits;
  u32 map_size_batched = (afl->fsrv.real_map_size + 7) >> 3;
  u32 *num_of_children = afl->fsrv.num_of_children;
  u32 *border_edge_parent_first_id = afl->fsrv.border_edge_parent_first_id;
  u32 *border_edge_child = afl->fsrv.border_edge_child;
  u8 *virgin_bits = afl->virgin_bits;
  struct queue_entry **wd_scheduler_top_rated = afl->wd_scheduler_top_rated;
  struct queue_entry ***border_edge_seed_list = afl->fsrv.border_edge_seed_list;
  u32 *border_edge_seed_list_cnt = afl->fsrv.border_edge_seed_list_cnt;
  u32 *border_edge_seed_list_capacity = afl->fsrv.border_edge_seed_list_capacity;
  u64 *spent_time_us = afl->fsrv.spent_time_us;
  u64 *productive_time_us = afl->fsrv.productive_time_us;
  u8 *cmp_type = afl->fsrv.cmp_type;
  u32 *added_seeds = afl->fsrv.added_seeds;
  u32 *border_edge_2_br_dist = afl->fsrv.border_edge_2_br_dist;
  u8 *size_gradient_checked = afl->fsrv.size_gradient_checked;
  u8 *br_cov = afl->fsrv.br_cov;
  u32 max_added_seeds = afl->max_added_seeds;
  u8 shared_mode = afl->wd_scheduler_shared_mode;

  u32 border_edge_cnt = 0;
  u32 nar_border_edge_cnt = 0;
  u32 max_weight_border_edge_id = 0;
  u32 max_weight_nar_border_edge_id = 0;
  double max_weight = -DBL_MAX;
  double max_weight_nar = -DBL_MAX;
  double total_weight = 0.0;
  double nar_total_weight = 0.0;
  u64 total_frontier_discovery_time_us = 0;
#ifdef WD_SCHED_BREAK_TIE_FASTER_SEED
  u32 min_exec_us_border_edge_id = 0;
  u64 min_exec_us = UINT64_MAX;
#endif
  u32 skipped_edge_cnt = 0;
  u32 handler_edge_cnt = 0;

  for (u32 i = 0; i < map_size_batched; i++) {
    if (likely(cur_virgin_bit_batch[i] == 0xffffffffffffffff))
      continue;

    u8 *cur_virgin_bit = (u8 *)(cur_virgin_bit_batch + i);
    for (u32 j = 0; j < 8; j++) {
      if (cur_virgin_bit[j] == 0xff)
        continue;

      u32 parent = i * 8 + j;

      u32 cur_num_of_children = num_of_children[parent];

      // only check conditional branches
      if (cur_num_of_children < 2)
        continue;

      u32 base_border_edge_id = border_edge_parent_first_id[parent];
      u8 cmp_type_parent = cmp_type[parent];
      u8 handler = is_handler(cmp_type_parent);
      for (u32 cur_border_edge_id = base_border_edge_id; cur_border_edge_id < base_border_edge_id + cur_num_of_children; cur_border_edge_id++) {
        u32 child_node = border_edge_child[cur_border_edge_id];

        // release resources for non-horizon branch seed lists
        if (was_reached(child_node, virgin_bits)) {
          if (border_edge_seed_list[cur_border_edge_id]) {
            ck_free(border_edge_seed_list[cur_border_edge_id]);
            border_edge_seed_list[cur_border_edge_id] = 0;
            border_edge_seed_list_cnt[cur_border_edge_id] = 0;
            border_edge_seed_list_capacity[cur_border_edge_id] = 0;
          }
          continue;
        }

        struct queue_entry *top_seed = top_rated_seed(afl, cur_border_edge_id, parent);
        if (!top_seed)
          continue;

        // compute border edge weight
        double border_edge_weight = - log(spent_time_us[parent]) - log1p(top_seed->schedule_cnt);
        if (!shared_mode && cmp_type_parent != NOT_INSTRUMENTED)
          border_edge_weight += log(productive_time_us[cur_border_edge_id]);

        // update max
        if (cmp_type_parent == NOT_INSTRUMENTED) {
          nar_total_weight += border_edge_weight;
          if (isgreaterequal(border_edge_weight, max_weight_nar)) {
            max_weight_nar_border_edge_id = cur_border_edge_id;
            max_weight_nar = border_edge_weight;
          }
          nar_border_edge_cnt++;
        } else if (added_seeds[cur_border_edge_id] < max_added_seeds) {
          u32 br_dist_edge_id = border_edge_2_br_dist[cur_border_edge_id];
          if (!br_cov[br_dist_edge_id] && !size_gradient_checked[br_dist_edge_id]) {
#ifdef WD_SCHED_BREAK_TIE_FASTER_SEED
            if (spent_time_us[cur_border_edge_id] == 1) {
              u64 seed_exec_us = top_seed->exec_us;
              if (seed_exec_us < min_exec_us) {
                min_exec_us = seed_exec_us;
                min_exec_us_border_edge_id = cur_border_edge_id;
              }
            }
#endif
            if (isgreaterequal(border_edge_weight, max_weight)) {
              max_weight_border_edge_id = cur_border_edge_id;
              max_weight = border_edge_weight;
            }
          } else {
            skipped_edge_cnt++;
          }
        } else {
          skipped_edge_cnt++;
        }

        // update counters
        border_edge_cnt++;
        handler_edge_cnt += handler;
        total_weight += border_edge_weight;
        total_frontier_discovery_time_us += LINE_SEARCH_MIN_MUTANTS * top_seed->exec_us;
      }
    }
  }

  if (!border_edge_cnt)
    PFATAL("BUG: no horizon branches traversed.");

  afl->wd_scheduler_shared_mode = total_frontier_discovery_time_us > MAX_TOTAL_FRONTIER_DISCOVERY_TIME_US;
  afl->max_added_seeds = afl->wd_scheduler_shared_mode ? MAX_ADDED_SEEDS_SHARED : MAX_ADDED_SEEDS;

#ifdef WD_SCHED_BREAK_TIE_FASTER_SEED
  if (min_exec_us < UINT64_MAX)
    max_weight_border_edge_id = min_exec_us_border_edge_id;
#endif

  afl->wd_scheduler_selected_border_edge_idx = max_weight_border_edge_id;

  u8 selected_nar = 0;

  // AS: select a NAR branch with a probability p = nar_border_edge_count / border_edge_count
  if (rand_next_percent(afl) < (double) nar_border_edge_cnt / border_edge_cnt) {
    // AS: select a random NAR branch
    if (border_edge_seed_list_cnt[max_weight_nar_border_edge_id]) {
      // AS: select a seed at random from the NAR branch's seed_list
      struct queue_entry *q = get_least_scheduled_seed(
          border_edge_seed_list[max_weight_nar_border_edge_id],
          border_edge_seed_list_cnt[max_weight_nar_border_edge_id]);

      if (q) {
        afl->wd_scheduler_selected_border_edge_idx = max_weight_nar_border_edge_id;
        wd_scheduler_top_rated[max_weight_nar_border_edge_id] = q;
        selected_nar = 1;
      }
    }
#ifdef FOX_INTROSPECTION
    else {
      fprintf(afl->fsrv.fox_debug_log_file, "BUG: NAR edge has no associated seed list, defaulting to max weight edge.\n");
    }
#endif
  }

  if (!wd_scheduler_top_rated[afl->wd_scheduler_selected_border_edge_idx])
    FATAL("BUG: the selected horizon branch does not have an associated seed.");

  // update wd scheduler stats for the UI
  afl->wd_scheduler_stats.frontier_size = border_edge_cnt;
  afl->wd_scheduler_stats.frontier_instrumented = border_edge_cnt - nar_border_edge_cnt;
  afl->wd_scheduler_stats.frontier_skipped = skipped_edge_cnt;
  afl->wd_scheduler_stats.frontier_handled = handler_edge_cnt;
  afl->wd_scheduler_stats.frontier_discovery_time_min = total_frontier_discovery_time_us / 60000000;

  // update wd scheduler log
  fprintf(afl->fsrv.wd_scheduler_log_file, "%llu %u %u %f %f %u %f %u %f %u %u %u %u %llu %u\n",
      ((afl->prev_run_time + get_cur_time() - afl->start_time) / 1000),
      afl->wd_scheduler_selected_border_edge_idx,
      wd_scheduler_top_rated[afl->wd_scheduler_selected_border_edge_idx]->id,
      max_weight,
      max_weight_nar,
      selected_nar,
      nar_total_weight,
      nar_border_edge_cnt,
      total_weight,
      border_edge_cnt,
      handler_edge_cnt,
      skipped_edge_cnt,
      shared_mode,
      total_frontier_discovery_time_us,
      afl->queued_items);
  fflush(afl->fsrv.wd_scheduler_log_file);

  save_fox_metadata(afl);
#ifdef FOX_INTROSPECTION
  save_convexity_info(afl);
#endif
}

static inline void add_capacity(struct queue_entry ***seed_list_p, u32 *capacity_p) {
  u32 new_capacity = *capacity_p + 1024;
  struct queue_entry** seed_list = *seed_list_p;
  struct queue_entry** new_seed_list = ck_alloc(new_capacity * sizeof(struct queue_entry*));
  if (seed_list) {
    for (u32 seed_idx=0; seed_idx < *capacity_p; seed_idx++)
      new_seed_list[seed_idx] = seed_list[seed_idx];
    ck_free(seed_list);
  }
  *seed_list_p = new_seed_list;
  *capacity_p = new_capacity;
}

static inline void add_to_seed_list(afl_state_t *afl, u32 cur_border_edge_id, struct queue_entry *q) {
  struct queue_entry ***seed_list_p = afl->fsrv.border_edge_seed_list + cur_border_edge_id;
  u32 *cur_seed_cnt_p = afl->fsrv.border_edge_seed_list_cnt + cur_border_edge_id;
  u32 *capacity_p = afl->fsrv.border_edge_seed_list_capacity + cur_border_edge_id;

  if (*cur_seed_cnt_p >= *capacity_p)
    add_capacity(seed_list_p, capacity_p);

  (*seed_list_p)[(*cur_seed_cnt_p)++] = q;
}

/* There are total two cases when update_bitmap_score_wd_scheudler is called()
 * 1. perform_dry_run()->calibrate_case_dry_run()->update_bitmap_score_wd_scheduler_dry_run()
 *    In this case, all the testcases already exist in the seed queue, hence save_if_interesting() would not be invoked. And as a result, the logic to associate each seed to the top_rated list is not called. So we add these logic in this update_bitmap_score_wd_scheduler_dry_run()
 * 2. save_if_interesting()->calibrate_case()->update_bitmap_score_wd_scheduler()
 */
void update_bitmap_score_wd_scheduler(afl_state_t *afl, struct queue_entry* q) {

  u64 *cur_trace_bit_batch = (u64 *)afl->fsrv.trace_bits;
  u32 map_size_batched = ((afl->fsrv.real_map_size + 7) >> 3);
  u32 *num_of_children = afl->fsrv.num_of_children;
  u32 *border_edge_parent_first_id = afl->fsrv.border_edge_parent_first_id;
  u32 *border_edge_child = afl->fsrv.border_edge_child;
  u8 *virgin_bits = afl->virgin_bits;
  u8 *cmp_type = afl->fsrv.cmp_type;

  // Check a sparse array faster by batching eight u8 ptrs as one u64 ptr.
  for (u32 i = 0; i < map_size_batched; i++) {
    if (likely(!cur_trace_bit_batch[i]))
      continue;

    u8 *cur_trace_bit = (u8 *)(cur_trace_bit_batch + i);

    for (u32 j = 0; j < 8; j++){
      if (!cur_trace_bit[j])
        continue;

      u32 parent = i * 8 + j;

      u32 cur_num_of_children = num_of_children[parent];

      if (cur_num_of_children < 2 || cmp_type[parent] != NOT_INSTRUMENTED)
        continue;

      u32 base_border_edge_id = border_edge_parent_first_id[parent];
      for (u32 cur_border_edge_id = base_border_edge_id; cur_border_edge_id < base_border_edge_id + cur_num_of_children; cur_border_edge_id++) {
        u32 child_node = border_edge_child[cur_border_edge_id];
        if (was_reached(child_node, virgin_bits))
          continue;
        add_to_seed_list(afl, cur_border_edge_id, q);
      }
    }
  }
}

/* create the alias table that allows weighted random selection - expensive */

void create_alias_table(afl_state_t *afl) {

  u32    n = afl->queued_items, i = 0, nSmall = 0, nLarge = n - 1;
  double sum = 0;

  double *P = (double *)afl_realloc(AFL_BUF_PARAM(out), n * sizeof(double));
  u32 *Small = (int *)afl_realloc(AFL_BUF_PARAM(out_scratch), n * sizeof(u32));
  u32 *Large = (int *)afl_realloc(AFL_BUF_PARAM(in_scratch), n * sizeof(u32));

  afl->alias_table =
      (u32 *)afl_realloc((void **)&afl->alias_table, n * sizeof(u32));
  afl->alias_probability = (double *)afl_realloc(
      (void **)&afl->alias_probability, n * sizeof(double));

  if (!P || !Small || !Large || !afl->alias_table || !afl->alias_probability) {

    FATAL("could not acquire memory for alias table");

  }

  memset((void *)afl->alias_probability, 0, n * sizeof(double));
  memset((void *)afl->alias_table, 0, n * sizeof(u32));
  memset((void *)Small, 0, n * sizeof(u32));
  memset((void *)Large, 0, n * sizeof(u32));

  if (likely(afl->schedule < RARE)) {

    double avg_exec_us = 0.0;
    double avg_bitmap_size = 0.0;
    double avg_top_size = 0.0;
    u32    active = 0;

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      // disabled entries might have timings and bitmap values
      if (likely(!q->disabled)) {

        avg_exec_us += q->exec_us;
        avg_bitmap_size += log(q->bitmap_size);
        avg_top_size += q->tc_ref;
        ++active;

      }

    }

    avg_exec_us /= active;
    avg_bitmap_size /= active;
    avg_top_size /= active;

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      if (likely(!q->disabled)) {

        q->weight =
            compute_weight(afl, q, avg_exec_us, avg_bitmap_size, avg_top_size);
        q->perf_score = calculate_score(afl, q);
        sum += q->weight;

      }

    }

    if (unlikely(afl->schedule == MMOPT) && afl->queued_discovered) {

      u32 cnt = afl->queued_discovered >= 5 ? 5 : afl->queued_discovered;

      for (i = n - cnt; i < n; i++) {

        struct queue_entry *q = afl->queue_buf[i];

        if (likely(!q->disabled)) { q->weight *= 2.0; }

      }

    }

    for (i = 0; i < n; i++) {

      // weight is always 0 for disabled entries
      if (unlikely(afl->queue_buf[i]->disabled)) {

        P[i] = 0;

      } else {

        P[i] = (afl->queue_buf[i]->weight * n) / sum;

      }

    }

  } else {

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      if (likely(!q->disabled)) {

        q->perf_score = calculate_score(afl, q);
        sum += q->perf_score;

      }

    }

    for (i = 0; i < n; i++) {

      // perf_score is always 0 for disabled entries
      if (unlikely(afl->queue_buf[i]->disabled)) {

        P[i] = 0;

      } else {

        P[i] = (afl->queue_buf[i]->perf_score * n) / sum;

      }

    }

  }

  // Done collecting weightings in P, now create the arrays.

  for (s32 j = (s32)(n - 1); j >= 0; j--) {

    if (P[j] < 1) {

      Small[nSmall++] = (u32)j;

    } else {

      Large[nLarge--] = (u32)j;

    }

  }

  while (nSmall && nLarge != n - 1) {

    u32 small = Small[--nSmall];
    u32 large = Large[++nLarge];

    afl->alias_probability[small] = P[small];
    afl->alias_table[small] = large;

    P[large] = P[large] - (1 - P[small]);

    if (P[large] < 1) {

      Small[nSmall++] = large;

    } else {

      Large[nLarge--] = large;

    }

  }

  while (nSmall) {

    afl->alias_probability[Small[--nSmall]] = 1;

  }

  while (nLarge != n - 1) {

    afl->alias_probability[Large[++nLarge]] = 1;

  }

  afl->reinit_table = 0;

  /*
  #ifdef INTROSPECTION
    u8 fn[PATH_MAX];
    snprintf(fn, PATH_MAX, "%s/introspection_corpus.txt", afl->out_dir);
    FILE *f = fopen(fn, "a");
    if (f) {

      for (i = 0; i < n; i++) {

        struct queue_entry *q = afl->queue_buf[i];
        fprintf(
            f,
            "entry=%u name=%s favored=%s variable=%s disabled=%s len=%u "
            "exec_us=%u "
            "bitmap_size=%u bitsmap_size=%u tops=%u weight=%f perf_score=%f\n",
            i, q->fname, q->favored ? "true" : "false",
            q->var_behavior ? "true" : "false", q->disabled ? "true" : "false",
            q->len, (u32)q->exec_us, q->bitmap_size, q->bitsmap_size, q->tc_ref,
            q->weight, q->perf_score);

      }

      fprintf(f, "\n");
      fclose(f);

    }

  #endif
  */
  /*
  fprintf(stderr, "  entry  alias  probability  perf_score   weight
  filename\n"); for (i = 0; i < n; ++i) fprintf(stderr, "  %5u  %5u  %11u
  %0.9f  %0.9f  %s\n", i, afl->alias_table[i], afl->alias_probability[i],
  afl->queue_buf[i]->perf_score, afl->queue_buf[i]->weight,
            afl->queue_buf[i]->fname);
  */

}

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

void mark_as_det_done(afl_state_t *afl, struct queue_entry *q) {

  char fn[PATH_MAX];
  s32  fd;

  snprintf(fn, PATH_MAX, "%s/queue/.state/deterministic_done/%s", afl->out_dir,
           strrchr((char *)q->fname, '/') + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (fd < 0) { PFATAL("Unable to create '%s'", fn); }
  close(fd);

  q->passed_det = 1;

}

/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

void mark_as_variable(afl_state_t *afl, struct queue_entry *q) {

  char fn[PATH_MAX];
  char ldest[PATH_MAX];

  char *fn_name = strrchr((char *)q->fname, '/') + 1;

  sprintf(ldest, "../../%s", fn_name);
  sprintf(fn, "%s/queue/.state/variable_behavior/%s", afl->out_dir, fn_name);

  if (symlink(ldest, fn)) {

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (fd < 0) { PFATAL("Unable to create '%s'", fn); }
    close(fd);

  }

  q->var_behavior = 1;

}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

void mark_as_redundant(afl_state_t *afl, struct queue_entry *q, u8 state) {

  if (likely(state == q->fs_redundant)) { return; }

  char fn[PATH_MAX];

  q->fs_redundant = state;

  sprintf(fn, "%s/queue/.state/redundant_edges/%s", afl->out_dir,
          strrchr((char *)q->fname, '/') + 1);

  if (state) {

    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (fd < 0) { PFATAL("Unable to create '%s'", fn); }
    close(fd);

  } else {

    if (unlink(fn)) { PFATAL("Unable to remove '%s'", fn); }

  }

}

/* check if pointer is ascii or UTF-8 */

u8 check_if_text_buf(u8 *buf, u32 len) {

  u32 offset = 0, ascii = 0, utf8 = 0;

  while (offset < len) {

    // ASCII: <= 0x7F to allow ASCII control characters
    if ((buf[offset + 0] == 0x09 || buf[offset + 0] == 0x0A ||
         buf[offset + 0] == 0x0D ||
         (0x20 <= buf[offset + 0] && buf[offset + 0] <= 0x7E))) {

      offset++;
      utf8++;
      ascii++;
      continue;

    }

    if (isascii((int)buf[offset]) || isprint((int)buf[offset])) {

      ascii++;
      // we continue though as it can also be a valid utf8

    }

    // non-overlong 2-byte
    if (len - offset > 1 &&
        ((0xC2 <= buf[offset + 0] && buf[offset + 0] <= 0xDF) &&
         (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF))) {

      offset += 2;
      utf8++;
      continue;

    }

    // excluding overlongs
    if ((len - offset > 2) &&
        ((buf[offset + 0] == 0xE0 &&
          (0xA0 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // straight 3-byte
         (((0xE1 <= buf[offset + 0] && buf[offset + 0] <= 0xEC) ||
           buf[offset + 0] == 0xEE || buf[offset + 0] == 0xEF) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // excluding surrogates
         (buf[offset + 0] == 0xED &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x9F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF)))) {

      offset += 3;
      utf8++;
      continue;

    }

    // planes 1-3
    if ((len - offset > 3) &&
        ((buf[offset + 0] == 0xF0 &&
          (0x90 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] &&
           buf[offset + 3] <= 0xBF)) ||  // planes 4-15
         ((0xF1 <= buf[offset + 0] && buf[offset + 0] <= 0xF3) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)) ||  // plane 16
         (buf[offset + 0] == 0xF4 &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x8F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)))) {

      offset += 4;
      utf8++;
      continue;

    }

    offset++;

  }

  return (utf8 > ascii ? utf8 : ascii);

}

/* check if queue entry is ascii or UTF-8 */

static u8 check_if_text(afl_state_t *afl, struct queue_entry *q) {

  if (q->len < AFL_TXT_MIN_LEN || q->len < AFL_TXT_MAX_LEN) return 0;

  u8     *buf;
  int     fd;
  u32     len = q->len, offset = 0, ascii = 0, utf8 = 0;
  ssize_t comp;

  if (len >= MAX_FILE) len = MAX_FILE - 1;
  if ((fd = open((char *)q->fname, O_RDONLY)) < 0) return 0;
  buf = (u8 *)afl_realloc(AFL_BUF_PARAM(in_scratch), len + 1);
  comp = read(fd, buf, len);
  close(fd);
  if (comp != (ssize_t)len) return 0;
  buf[len] = 0;

  while (offset < len) {

    // ASCII: <= 0x7F to allow ASCII control characters
    if ((buf[offset + 0] == 0x09 || buf[offset + 0] == 0x0A ||
         buf[offset + 0] == 0x0D ||
         (0x20 <= buf[offset + 0] && buf[offset + 0] <= 0x7E))) {

      offset++;
      utf8++;
      ascii++;
      continue;

    }

    if (isascii((int)buf[offset]) || isprint((int)buf[offset])) {

      ascii++;
      // we continue though as it can also be a valid utf8

    }

    // non-overlong 2-byte
    if (len - offset > 1 &&
        ((0xC2 <= buf[offset + 0] && buf[offset + 0] <= 0xDF) &&
         (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF))) {

      offset += 2;
      utf8++;
      comp--;
      continue;

    }

    // excluding overlongs
    if ((len - offset > 2) &&
        ((buf[offset + 0] == 0xE0 &&
          (0xA0 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // straight 3-byte
         (((0xE1 <= buf[offset + 0] && buf[offset + 0] <= 0xEC) ||
           buf[offset + 0] == 0xEE || buf[offset + 0] == 0xEF) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // excluding surrogates
         (buf[offset + 0] == 0xED &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x9F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF)))) {

      offset += 3;
      utf8++;
      comp -= 2;
      continue;

    }

    // planes 1-3
    if ((len - offset > 3) &&
        ((buf[offset + 0] == 0xF0 &&
          (0x90 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] &&
           buf[offset + 3] <= 0xBF)) ||  // planes 4-15
         ((0xF1 <= buf[offset + 0] && buf[offset + 0] <= 0xF3) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)) ||  // plane 16
         (buf[offset + 0] == 0xF4 &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x8F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)))) {

      offset += 4;
      utf8++;
      comp -= 3;
      continue;

    }

    offset++;

  }

  u32 percent_utf8 = (utf8 * 100) / comp;
  u32 percent_ascii = (ascii * 100) / len;

  if (percent_utf8 >= percent_ascii && percent_utf8 >= AFL_TXT_MIN_PERCENT)
    return 2;
  if (percent_ascii >= AFL_TXT_MIN_PERCENT) return 1;
  return 0;

}

/* Append new test case to the queue. */

void add_to_queue(afl_state_t *afl, u8 *fname, u32 len, u8 passed_det) {

  struct queue_entry *q =
      (struct queue_entry *)ck_alloc(sizeof(struct queue_entry));

  q->fname = fname;
  q->len = len;
  q->depth = afl->cur_depth + 1;
  q->passed_det = passed_det;
  q->trace_mini = NULL;
  q->testcase_buf = NULL;
  q->mother = afl->queue_cur;

#ifdef INTROSPECTION
  q->bitsmap_size = afl->bitsmap_size;
#endif

  if (q->depth > afl->max_depth) { afl->max_depth = q->depth; }

  if (afl->queue_top) {

    afl->queue_top = q;

  } else {

    afl->queue = afl->queue_top = q;

  }

  if (likely(q->len > 4)) { ++afl->ready_for_splicing_count; }

  ++afl->queued_items;
  ++afl->active_items;
  ++afl->pending_not_fuzzed;

  afl->cycles_wo_finds = 0;

  struct queue_entry **queue_buf = (struct queue_entry **)afl_realloc(
      AFL_BUF_PARAM(queue), afl->queued_items * sizeof(struct queue_entry *));
  if (unlikely(!queue_buf)) { PFATAL("alloc"); }
  queue_buf[afl->queued_items - 1] = q;
  q->id = afl->queued_items - 1;

  u64 cur_time = get_cur_time();

  if (likely(afl->start_time) &&
      unlikely(afl->longest_find_time < cur_time - afl->last_find_time)) {

    if (unlikely(!afl->last_find_time)) {

      afl->longest_find_time = cur_time - afl->start_time;

    } else {

      afl->longest_find_time = cur_time - afl->last_find_time;

    }

  }

  afl->last_find_time = cur_time;

  if (afl->custom_mutators_count) {

    /* At the initialization stage, queue_cur is NULL */
    if (afl->queue_cur && !afl->syncing_party) {

      run_afl_custom_queue_new_entry(afl, q, fname, afl->queue_cur->fname);

    }

  }

  /* only redqueen currently uses is_ascii */
  if (unlikely(afl->shm.cmplog_mode && !q->is_ascii)) {

    q->is_ascii = check_if_text(afl, q);

  }

}

/* Destroy the entire queue. */

void destroy_queue(afl_state_t *afl) {

  u32 i;

  for (i = 0; i < afl->queued_items; i++) {

    struct queue_entry *q;

    q = afl->queue_buf[i];
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q);

  }

}

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of afl->top_rated[]
   entries for every byte in the bitmap. We win that slot if there is no
   previous contender, or if the contender has a more favorable speed x size
   factor. */

void update_bitmap_score(afl_state_t *afl, struct queue_entry *q) {

  u32 i;
  u64 fav_factor;
  u64 fuzz_p2;

  if (likely(afl->schedule >= FAST && afl->schedule < RARE)) {

    fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

  } else if (unlikely(afl->schedule == RARE)) {

    fuzz_p2 = next_pow2(afl->n_fuzz[q->n_fuzz_entry]);

  } else {

    fuzz_p2 = q->fuzz_level;

  }

  if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {

    fav_factor = q->len << 2;

  } else {

    fav_factor = q->exec_us * q->len;

  }

  /* For every byte set in afl->fsrv.trace_bits[], see if there is a previous
     winner, and how it compares to us. */
  for (i = 0; i < afl->fsrv.map_size; ++i) {

    if (afl->fsrv.trace_bits[i]) {

      if (afl->top_rated[i]) {

        /* Faster-executing or smaller test cases are favored. */
        u64 top_rated_fav_factor;
        u64 top_rated_fuzz_p2;

        if (likely(afl->schedule >= FAST && afl->schedule < RARE)) {

          top_rated_fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

        } else if (unlikely(afl->schedule == RARE)) {

          top_rated_fuzz_p2 =
              next_pow2(afl->n_fuzz[afl->top_rated[i]->n_fuzz_entry]);

        } else {

          top_rated_fuzz_p2 = afl->top_rated[i]->fuzz_level;

        }

        if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {

          top_rated_fav_factor = afl->top_rated[i]->len << 2;

        } else {

          top_rated_fav_factor =
              afl->top_rated[i]->exec_us * afl->top_rated[i]->len;

        }

        if (likely(fuzz_p2 > top_rated_fuzz_p2)) { continue; }

        if (likely(fav_factor > top_rated_fav_factor)) { continue; }

        /* Looks like we're going to win. Decrease ref count for the
           previous winner, discard its afl->fsrv.trace_bits[] if necessary. */

        if (!--afl->top_rated[i]->tc_ref) {

          ck_free(afl->top_rated[i]->trace_mini);
          afl->top_rated[i]->trace_mini = 0;

        }

      }

      /* Insert ourselves as the new winner. */

      afl->top_rated[i] = q;
      ++q->tc_ref;

      if (!q->trace_mini) {

        u32 len = (afl->fsrv.map_size >> 3);
        q->trace_mini = (u8 *)ck_alloc(len);
        minimize_bits(afl, q->trace_mini, afl->fsrv.trace_bits);

      }

      afl->score_changed = 1;

    }

  }

}

/* The second part of the mechanism discussed above is a routine that
   goes over afl->top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

void cull_queue(afl_state_t *afl) {

  if (likely(afl->schedule == WD_SCHEDULER || !afl->score_changed || afl->non_instrumented_mode)) { return; }

  u32 len = (afl->fsrv.map_size >> 3);
  u32 i;
  u8 *temp_v = afl->map_tmp_buf;

  afl->score_changed = 0;

  memset(temp_v, 255, len);

  afl->queued_favored = 0;
  afl->pending_favored = 0;

  for (i = 0; i < afl->queued_items; i++) {

    afl->queue_buf[i]->favored = 0;

  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a afl->top_rated[] contender, let's use it. */

  afl->smallest_favored = -1;

  for (i = 0; i < afl->fsrv.map_size; ++i) {

    if (afl->top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = len;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) {

        if (afl->top_rated[i]->trace_mini[j]) {

          temp_v[j] &= ~afl->top_rated[i]->trace_mini[j];

        }

      }

      if (!afl->top_rated[i]->favored) {

        afl->top_rated[i]->favored = 1;
        ++afl->queued_favored;

        if (!afl->top_rated[i]->was_fuzzed) {

          ++afl->pending_favored;
          if (unlikely(afl->smallest_favored < 0)) {

            afl->smallest_favored = (s64)afl->top_rated[i]->id;

          }

        }

      }

    }

  }

  for (i = 0; i < afl->queued_items; i++) {

    if (likely(!afl->queue_buf[i]->disabled)) {

      mark_as_redundant(afl, afl->queue_buf[i], !afl->queue_buf[i]->favored);

    }

  }

  afl->reinit_table = 1;

}

/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

u32 calculate_score(afl_state_t *afl, struct queue_entry *q) {

  u32 cal_cycles = afl->total_cal_cycles;
  u32 bitmap_entries = afl->total_bitmap_entries;

  if (unlikely(!cal_cycles)) { cal_cycles = 1; }
  if (unlikely(!bitmap_entries)) { bitmap_entries = 1; }

  u32 avg_exec_us = afl->total_cal_us / cal_cycles;
  u32 avg_bitmap_size = afl->total_bitmap_size / bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  // TODO BUG FIXME: is this really a good idea?
  // This sounds like looking for lost keys under a street light just because
  // the light is better there.
  // Longer execution time means longer work on the input, the deeper in
  // coverage, the better the fuzzing, right? -mh

  if (likely(afl->schedule < RARE) && likely(!afl->fixed_seed)) {

    if (q->exec_us * 0.1 > avg_exec_us) {

      perf_score = 10;

    } else if (q->exec_us * 0.25 > avg_exec_us) {

      perf_score = 25;

    } else if (q->exec_us * 0.5 > avg_exec_us) {

      perf_score = 50;

    } else if (q->exec_us * 0.75 > avg_exec_us) {

      perf_score = 75;

    } else if (q->exec_us * 4 < avg_exec_us) {

      perf_score = 300;

    } else if (q->exec_us * 3 < avg_exec_us) {

      perf_score = 200;

    } else if (q->exec_us * 2 < avg_exec_us) {

      perf_score = 150;

    }

  }

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) {

    perf_score *= 3;

  } else if (q->bitmap_size * 0.5 > avg_bitmap_size) {

    perf_score *= 2;

  } else if (q->bitmap_size * 0.75 > avg_bitmap_size) {

    perf_score *= 1.5;

  } else if (q->bitmap_size * 3 < avg_bitmap_size) {

    perf_score *= 0.25;

  } else if (q->bitmap_size * 2 < avg_bitmap_size) {

    perf_score *= 0.5;

  } else if (q->bitmap_size * 1.5 < avg_bitmap_size) {

    perf_score *= 0.75;

  }

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    --q->handicap;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:
      break;
    case 4 ... 7:
      perf_score *= 2;
      break;
    case 8 ... 13:
      perf_score *= 3;
      break;
    case 14 ... 25:
      perf_score *= 4;
      break;
    default:
      perf_score *= 5;

  }

  u32         n_items;
  double      factor = 1.0;
  long double fuzz_mu;

  switch (afl->schedule) {

    case EXPLORE:
      break;

    case SEEK:
      break;

    case EXPLOIT:
      factor = MAX_FACTOR;
      break;

    case COE:
      fuzz_mu = 0.0;
      n_items = 0;

      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      u32 i;
      for (i = 0; i < afl->queued_items; i++) {

        if (likely(!afl->queue_buf[i]->disabled)) {

          fuzz_mu += log2(afl->n_fuzz[afl->queue_buf[i]->n_fuzz_entry]);
          n_items++;

        }

      }

      if (unlikely(!n_items)) { FATAL("Queue state corrupt"); }

      fuzz_mu = fuzz_mu / n_items;

      if (log2(afl->n_fuzz[q->n_fuzz_entry]) > fuzz_mu) {

        /* Never skip favourites */
        if (!q->favored) factor = 0;

        break;

      }

    // Fall through
    case FAST:

      // Don't modify unfuzzed seeds
      if (!q->fuzz_level) break;

      switch ((u32)log2(afl->n_fuzz[q->n_fuzz_entry])) {

        case 0 ... 1:
          factor = 4;
          break;

        case 2 ... 3:
          factor = 3;
          break;

        case 4:
          factor = 2;
          break;

        case 5:
          break;

        case 6:
          if (!q->favored) factor = 0.8;
          break;

        case 7:
          if (!q->favored) factor = 0.6;
          break;

        default:
          if (!q->favored) factor = 0.4;
          break;

      }

      if (q->favored) factor *= 1.15;

      break;

    case LIN:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      factor = q->fuzz_level / (afl->n_fuzz[q->n_fuzz_entry] + 1);
      break;

    case QUAD:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      factor =
          q->fuzz_level * q->fuzz_level / (afl->n_fuzz[q->n_fuzz_entry] + 1);
      break;

    case MMOPT:
      /* -- this was a more complex setup, which is good, but competed with
         -- rare. the simpler algo however is good when rare is not.
        // the newer the entry, the higher the pref_score
        perf_score *= (1 + (double)((double)q->depth /
        (double)afl->queued_items));
        // with special focus on the last 8 entries
        if (afl->max_depth - q->depth < 8) perf_score *= (1 + ((8 -
        (afl->max_depth - q->depth)) / 5));
      */
      // put focus on the last 5 entries
      if (afl->max_depth - q->depth < 5) { perf_score *= 2; }

      break;

    case RARE:

      // increase the score for every bitmap byte for which this entry
      // is the top contender
      perf_score += (q->tc_ref * 10);
      // the more often fuzz result paths are equal to this queue entry,
      // reduce its value
      perf_score *= (1 - (double)((double)afl->n_fuzz[q->n_fuzz_entry] /
                                  (double)afl->fsrv.total_execs));

      break;

    default:
      PFATAL("Unknown Power Schedule");

  }

  if (unlikely(afl->schedule >= EXPLOIT && afl->schedule <= QUAD)) {

    if (factor > MAX_FACTOR) { factor = MAX_FACTOR; }
    perf_score *= factor / POWER_BETA;

  }

  // MOpt mode
  if (afl->limit_time_sig != 0 && afl->max_depth - q->depth < 3) {

    perf_score *= 2;

  } else if (afl->schedule != COE && perf_score < 1) {

    // Add a lower bound to AFLFast's energy assignment strategies
    perf_score = 1;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > afl->havoc_max_mult * 100) {

    perf_score = afl->havoc_max_mult * 100;

  }

  return perf_score;

}

/* after a custom trim we need to reload the testcase from disk */

inline void queue_testcase_retake(afl_state_t *afl, struct queue_entry *q,
                                  u32 old_len) {

  if (likely(q->testcase_buf)) {

    u32 len = q->len;

    if (len != old_len) {

      afl->q_testcase_cache_size = afl->q_testcase_cache_size + len - old_len;
      q->testcase_buf = (u8 *)realloc(q->testcase_buf, len);

      if (unlikely(!q->testcase_buf)) {

        PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

      }

    }

    int fd = open((char *)q->fname, O_RDONLY);

    if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

    ck_read(fd, q->testcase_buf, len, q->fname);
    close(fd);

  }

}

/* after a normal trim we need to replace the testcase with the new data */

inline void queue_testcase_retake_mem(afl_state_t *afl, struct queue_entry *q,
                                      u8 *in, u32 len, u32 old_len) {

  if (likely(q->testcase_buf)) {

    u32 is_same = in == q->testcase_buf;

    if (likely(len != old_len)) {

      u8 *ptr = (u8 *)realloc(q->testcase_buf, len);

      if (likely(ptr)) {

        q->testcase_buf = ptr;
        afl->q_testcase_cache_size = afl->q_testcase_cache_size + len - old_len;

      }

    }

    if (unlikely(!is_same)) { memcpy(q->testcase_buf, in, len); }

  }

}

/* Returns the testcase buf from the file behind this queue entry.
  Increases the refcount. */

inline u8 *queue_testcase_get(afl_state_t *afl, struct queue_entry *q) {

  u32 len = q->len;

  /* first handle if no testcase cache is configured */

  if (unlikely(!afl->q_testcase_max_cache_size)) {

    u8 *buf;

    if (unlikely(q == afl->queue_cur)) {

      buf = (u8 *)afl_realloc((void **)&afl->testcase_buf, len);

    } else {

      buf = (u8 *)afl_realloc((void **)&afl->splicecase_buf, len);

    }

    if (unlikely(!buf)) {

      PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

    }

    int fd = open((char *)q->fname, O_RDONLY);

    if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

    ck_read(fd, buf, len, q->fname);
    close(fd);
    return buf;

  }

  /* now handle the testcase cache */

  if (unlikely(!q->testcase_buf)) {

    /* Buf not cached, let's load it */
    u32        tid = afl->q_testcase_max_cache_count;
    static u32 do_once = 0;  // because even threaded we would want this. WIP

    while (unlikely(
        afl->q_testcase_cache_size + len >= afl->q_testcase_max_cache_size ||
        afl->q_testcase_cache_count >= afl->q_testcase_max_cache_entries - 1)) {

      /* We want a max number of entries to the cache that we learn.
         Very simple: once the cache is filled by size - that is the max. */

      if (unlikely(afl->q_testcase_cache_size + len >=
                       afl->q_testcase_max_cache_size &&
                   (afl->q_testcase_cache_count <
                        afl->q_testcase_max_cache_entries &&
                    afl->q_testcase_max_cache_count <
                        afl->q_testcase_max_cache_entries) &&
                   !do_once)) {

        if (afl->q_testcase_max_cache_count > afl->q_testcase_cache_count) {

          afl->q_testcase_max_cache_entries =
              afl->q_testcase_max_cache_count + 1;

        } else {

          afl->q_testcase_max_cache_entries = afl->q_testcase_cache_count + 1;

        }

        do_once = 1;
        // release unneeded memory
        afl->q_testcase_cache = (struct queue_entry **)ck_realloc(
            afl->q_testcase_cache,
            (afl->q_testcase_max_cache_entries + 1) * sizeof(size_t));

      }

      /* Cache full. We neet to evict one or more to map one.
         Get a random one which is not in use */

      do {

        // if the cache (MB) is not enough for the queue then this gets
        // undesirable because q_testcase_max_cache_count grows sometimes
        // although the number of items in the cache will not change hence
        // more and more loops
        tid = rand_below(afl, afl->q_testcase_max_cache_count);

      } while (afl->q_testcase_cache[tid] == NULL ||

               afl->q_testcase_cache[tid] == afl->queue_cur);

      struct queue_entry *old_cached = afl->q_testcase_cache[tid];
      free(old_cached->testcase_buf);
      old_cached->testcase_buf = NULL;
      afl->q_testcase_cache_size -= old_cached->len;
      afl->q_testcase_cache[tid] = NULL;
      --afl->q_testcase_cache_count;
      ++afl->q_testcase_evictions;
      if (tid < afl->q_testcase_smallest_free)
        afl->q_testcase_smallest_free = tid;

    }

    if (unlikely(tid >= afl->q_testcase_max_cache_entries)) {

      // uh we were full, so now we have to search from start
      tid = afl->q_testcase_smallest_free;

    }

    // we need this while loop in case there were ever previous evictions but
    // not in this call.
    while (unlikely(afl->q_testcase_cache[tid] != NULL))
      ++tid;

    /* Map the test case into memory. */

    int fd = open((char *)q->fname, O_RDONLY);

    if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

    q->testcase_buf = (u8 *)malloc(len);

    if (unlikely(!q->testcase_buf)) {

      PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

    }

    ck_read(fd, q->testcase_buf, len, q->fname);
    close(fd);

    /* Register testcase as cached */
    afl->q_testcase_cache[tid] = q;
    afl->q_testcase_cache_size += len;
    ++afl->q_testcase_cache_count;
    if (likely(tid >= afl->q_testcase_max_cache_count)) {

      afl->q_testcase_max_cache_count = tid + 1;

    } else if (unlikely(tid == afl->q_testcase_smallest_free)) {

      afl->q_testcase_smallest_free = tid + 1;

    }

  }

  return q->testcase_buf;

}

/* Adds the new queue entry to the cache. */

inline void queue_testcase_store_mem(afl_state_t *afl, struct queue_entry *q,
                                     u8 *mem) {

  u32 len = q->len;

  if (unlikely(afl->q_testcase_cache_size + len >=
                   afl->q_testcase_max_cache_size ||
               afl->q_testcase_cache_count >=
                   afl->q_testcase_max_cache_entries - 1)) {

    // no space? will be loaded regularly later.
    return;

  }

  u32 tid;

  if (unlikely(afl->q_testcase_max_cache_count >=
               afl->q_testcase_max_cache_entries)) {

    // uh we were full, so now we have to search from start
    tid = afl->q_testcase_smallest_free;

  } else {

    tid = afl->q_testcase_max_cache_count;

  }

  while (unlikely(afl->q_testcase_cache[tid] != NULL))
    ++tid;

  /* Map the test case into memory. */

  q->testcase_buf = (u8 *)malloc(len);

  if (unlikely(!q->testcase_buf)) {

    PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

  }

  memcpy(q->testcase_buf, mem, len);

  /* Register testcase as cached */
  afl->q_testcase_cache[tid] = q;
  afl->q_testcase_cache_size += len;
  ++afl->q_testcase_cache_count;

  if (likely(tid >= afl->q_testcase_max_cache_count)) {

    afl->q_testcase_max_cache_count = tid + 1;

  } else if (unlikely(tid == afl->q_testcase_smallest_free)) {

    afl->q_testcase_smallest_free = tid + 1;

  }

}

