/*
 * Copyright (C) 2011, Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
 *
 * Parts came from builtin-{top,stat,record}.c, see those files for further
 * copyright notes.
 *
 * Released under the GPL v2. (and only v2, not any later version)
 */

#include "evsel.h"
#include "evlist.h"
#include "util.h"
#include "cpumap.h"
#include "thread_map.h"

#define FD(e, x, y) (*(int *)xyarray__entry(e->fd, x, y))

void perf_evsel__init(struct perf_evsel *evsel,
		      struct perf_event_attr *attr, int idx)
{
	evsel->idx	   = idx;
	evsel->attr	   = *attr;
	INIT_LIST_HEAD(&evsel->node);
	INIT_LIST_HEAD(&evsel->starter_list);
	INIT_LIST_HEAD(&evsel->stopper_list);
}

struct perf_evsel *perf_evsel__new(struct perf_event_attr *attr, int idx)
{
	struct perf_evsel *evsel = zalloc(sizeof(*evsel));

	if (evsel != NULL)
		perf_evsel__init(evsel, attr, idx);

	return evsel;
}

int perf_evsel__alloc_fd(struct perf_evsel *evsel, int ncpus, int nthreads)
{
	evsel->fd = xyarray__new(ncpus, nthreads, sizeof(int));
	return evsel->fd != NULL ? 0 : -ENOMEM;
}

int perf_evsel__alloc_id(struct perf_evsel *evsel, int ncpus, int nthreads)
{
	evsel->sample_id = xyarray__new(ncpus, nthreads, sizeof(struct perf_sample_id));
	if (evsel->sample_id == NULL)
		return -ENOMEM;

	evsel->id = zalloc(ncpus * nthreads * sizeof(u64));
	if (evsel->id == NULL) {
		xyarray__delete(evsel->sample_id);
		evsel->sample_id = NULL;
		return -ENOMEM;
	}

	return 0;
}

int perf_evsel__alloc_counts(struct perf_evsel *evsel, int ncpus)
{
	evsel->counts = zalloc((sizeof(*evsel->counts) +
				(ncpus * sizeof(struct perf_counts_values))));
	return evsel->counts != NULL ? 0 : -ENOMEM;
}

void perf_evsel__free_fd(struct perf_evsel *evsel)
{
	xyarray__delete(evsel->fd);
	evsel->fd = NULL;
}

void perf_evsel__free_id(struct perf_evsel *evsel)
{
	xyarray__delete(evsel->sample_id);
	evsel->sample_id = NULL;
	free(evsel->id);
	evsel->id = NULL;
}

void perf_evsel__close_fd(struct perf_evsel *evsel, int ncpus, int nthreads)
{
	int cpu, thread;

	for (cpu = 0; cpu < ncpus; cpu++)
		for (thread = 0; thread < nthreads; ++thread) {
			close(FD(evsel, cpu, thread));
			FD(evsel, cpu, thread) = -1;
		}
}

void perf_evsel__exit(struct perf_evsel *evsel)
{
	assert(list_empty(&evsel->node));
	xyarray__delete(evsel->fd);
	xyarray__delete(evsel->sample_id);
	free(evsel->id);
}

void perf_evsel__delete(struct perf_evsel *evsel)
{
	perf_evsel__exit(evsel);
	close_cgroup(evsel->cgrp);
	free(evsel->name);
	free(evsel);
}

int __perf_evsel__read_on_cpu(struct perf_evsel *evsel,
			      int cpu, int thread, bool scale)
{
	struct perf_counts_values count;
	size_t nv = scale ? 3 : 1;

	if (FD(evsel, cpu, thread) < 0)
		return -EINVAL;

	if (evsel->counts == NULL && perf_evsel__alloc_counts(evsel, cpu + 1) < 0)
		return -ENOMEM;

	if (readn(FD(evsel, cpu, thread), &count, nv * sizeof(u64)) < 0)
		return -errno;

	if (scale) {
		if (count.run == 0)
			count.val = 0;
		else if (count.run < count.ena)
			count.val = (u64)((double)count.val * count.ena / count.run + 0.5);
	} else
		count.ena = count.run = 0;

	evsel->counts->cpu[cpu] = count;
	return 0;
}

int __perf_evsel__read(struct perf_evsel *evsel,
		       int ncpus, int nthreads, bool scale)
{
	size_t nv = scale ? 3 : 1;
	int cpu, thread;
	struct perf_counts_values *aggr = &evsel->counts->aggr, count;

	aggr->val = aggr->ena = aggr->run = 0;

	for (cpu = 0; cpu < ncpus; cpu++) {
		for (thread = 0; thread < nthreads; thread++) {
			if (FD(evsel, cpu, thread) < 0)
				continue;

			if (readn(FD(evsel, cpu, thread),
				  &count, nv * sizeof(u64)) < 0)
				return -errno;

			aggr->val += count.val;
			if (scale) {
				aggr->ena += count.ena;
				aggr->run += count.run;
			}
		}
	}

	evsel->counts->scaled = 0;
	if (scale) {
		if (aggr->run == 0) {
			evsel->counts->scaled = -1;
			aggr->val = 0;
			return 0;
		}

		if (aggr->run < aggr->ena) {
			evsel->counts->scaled = 1;
			aggr->val = (u64)((double)aggr->val * aggr->ena / aggr->run + 0.5);
		}
	} else
		aggr->ena = aggr->run = 0;

	return 0;
}

static int __perf_evsel__open(struct perf_evsel *evsel, struct cpu_map *cpus,
			      struct thread_map *threads, bool group, bool inherit)
{
	int cpu, thread;
	unsigned long flags = 0;
	int pid = -1;

	if (evsel->fd == NULL &&
	    perf_evsel__alloc_fd(evsel, cpus->nr, threads->nr) < 0)
		return -1;

	if (evsel->cgrp) {
		flags = PERF_FLAG_PID_CGROUP;
		pid = evsel->cgrp->fd;
	}

	for (cpu = 0; cpu < cpus->nr; cpu++) {
		int group_fd = -1;
		/*
		 * Don't allow mmap() of inherited per-task counters. This
		 * would create a performance issue due to all children writing
		 * to the same buffer.
		 *
		 * FIXME:
		 * Proper fix is not to pass 'inherit' to perf_evsel__open*,
		 * but a 'flags' parameter, with 'group' folded there as well,
		 * then introduce a PERF_O_{MMAP,GROUP,INHERIT} enum, and if
		 * O_MMAP is set, emit a warning if cpu < 0 and O_INHERIT is
		 * set. Lets go for the minimal fix first tho.
		 */
		evsel->attr.inherit = (cpus->map[cpu] >= 0) && inherit;

		for (thread = 0; thread < threads->nr; thread++) {

			if (!evsel->cgrp)
				pid = threads->map[thread];

			FD(evsel, cpu, thread) = sys_perf_event_open(&evsel->attr,
								     pid,
								     cpus->map[cpu],
								     group_fd, flags);
			if (FD(evsel, cpu, thread) < 0)
				goto out_close;

			if (group && group_fd == -1)
				group_fd = FD(evsel, cpu, thread);
		}
	}

	return 0;

out_close:
	do {
		while (--thread >= 0) {
			close(FD(evsel, cpu, thread));
			FD(evsel, cpu, thread) = -1;
		}
		thread = threads->nr;
	} while (--cpu >= 0);
	return -1;
}

static struct {
	struct cpu_map map;
	int cpus[1];
} empty_cpu_map = {
	.map.nr	= 1,
	.cpus	= { -1, },
};

static struct {
	struct thread_map map;
	int threads[1];
} empty_thread_map = {
	.map.nr	 = 1,
	.threads = { -1, },
};

int perf_evsel__open(struct perf_evsel *evsel, struct cpu_map *cpus,
		     struct thread_map *threads, bool group, bool inherit)
{
	if (cpus == NULL) {
		/* Work around old compiler warnings about strict aliasing */
		cpus = &empty_cpu_map.map;
	}

	if (threads == NULL)
		threads = &empty_thread_map.map;

	return __perf_evsel__open(evsel, cpus, threads, group, inherit);
}

int perf_evsel__open_per_cpu(struct perf_evsel *evsel,
			     struct cpu_map *cpus, bool group, bool inherit)
{
	return __perf_evsel__open(evsel, cpus, &empty_thread_map.map, group, inherit);
}

int perf_evsel__open_per_thread(struct perf_evsel *evsel,
				struct thread_map *threads, bool group, bool inherit)
{
	return __perf_evsel__open(evsel, &empty_cpu_map.map, threads, group, inherit);
}

static int perf_event__parse_id_sample(const union perf_event *event, u64 type,
				       struct perf_sample *sample)
{
	const u64 *array = event->sample.array;

	array += ((event->header.size -
		   sizeof(event->header)) / sizeof(u64)) - 1;

	if (type & PERF_SAMPLE_CPU) {
		u32 *p = (u32 *)array;
		sample->cpu = *p;
		array--;
	}

	if (type & PERF_SAMPLE_STREAM_ID) {
		sample->stream_id = *array;
		array--;
	}

	if (type & PERF_SAMPLE_ID) {
		sample->id = *array;
		array--;
	}

	if (type & PERF_SAMPLE_TIME) {
		sample->time = *array;
		array--;
	}

	if (type & PERF_SAMPLE_TID) {
		u32 *p = (u32 *)array;
		sample->pid = p[0];
		sample->tid = p[1];
	}

	return 0;
}

int perf_event__parse_sample(const union perf_event *event, u64 type,
			     bool sample_id_all, struct perf_sample *data)
{
	const u64 *array;

	data->cpu = data->pid = data->tid = -1;
	data->stream_id = data->id = data->time = -1ULL;

	if (event->header.type != PERF_RECORD_SAMPLE) {
		if (!sample_id_all)
			return 0;
		return perf_event__parse_id_sample(event, type, data);
	}

	array = event->sample.array;

	if (type & PERF_SAMPLE_IP) {
		data->ip = event->ip.ip;
		array++;
	}

	if (type & PERF_SAMPLE_TID) {
		u32 *p = (u32 *)array;
		data->pid = p[0];
		data->tid = p[1];
		array++;
	}

	if (type & PERF_SAMPLE_TIME) {
		data->time = *array;
		array++;
	}

	if (type & PERF_SAMPLE_ADDR) {
		data->addr = *array;
		array++;
	}

	data->id = -1ULL;
	if (type & PERF_SAMPLE_ID) {
		data->id = *array;
		array++;
	}

	if (type & PERF_SAMPLE_STREAM_ID) {
		data->stream_id = *array;
		array++;
	}

	if (type & PERF_SAMPLE_CPU) {
		u32 *p = (u32 *)array;
		data->cpu = *p;
		array++;
	}

	if (type & PERF_SAMPLE_PERIOD) {
		data->period = *array;
		array++;
	}

	if (type & PERF_SAMPLE_READ) {
		fprintf(stderr, "PERF_SAMPLE_READ is unsuported for now\n");
		return -1;
	}

	if (type & PERF_SAMPLE_CALLCHAIN) {
		data->callchain = (struct ip_callchain *)array;
		array += 1 + data->callchain->nr;
	}

	if (type & PERF_SAMPLE_RAW) {
		u32 *p = (u32 *)array;
		data->raw_size = *p;
		p++;
		data->raw_data = p;
	}

	return 0;
}

int perf_evsel__set_filter(struct perf_evsel *evsel, int cpu,
			   int thread)
{
	char *filter;
	int fd;

	filter = evsel->filter;
	if (!filter)
		return 0;

	fd = FD(evsel, cpu, thread);

	return ioctl(fd, PERF_EVENT_IOC_SET_FILTER, filter);
}

int perf_evsel__set_starter(struct perf_evsel *evsel, int cpu,
			    int thread)
{
	struct perf_evsel *target;
	int fd, fd_target;
	int ret = 0;

	list_for_each_entry(target, &evsel->starter_list, starter_entry) {
		fd = FD(evsel, cpu, thread);
		fd_target = FD(target, cpu, thread);
		ret = ioctl(fd, PERF_EVENT_IOC_SET_STARTER, fd_target);
		if (ret)
			break;
	}

	return ret;
}

int perf_evsel__set_stopper(struct perf_evsel *evsel, int cpu,
			    int thread)
{
	struct perf_evsel *target;
	int fd, fd_target;
	int ret = 0;

	list_for_each_entry(target, &evsel->stopper_list, stopper_entry) {
		fd = FD(evsel, cpu, thread);
		fd_target = FD(target, cpu, thread);
		ret = ioctl(fd, PERF_EVENT_IOC_SET_STOPPER, fd_target);
		if (ret)
			break;
	}

	return ret;
}
