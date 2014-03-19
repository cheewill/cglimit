/*
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>

#include "libcgroup.h"

static struct option longopts[] = {
	{"help", no_argument, NULL, 'h'}, 
	{0, 0, 0, 0}
};

/* we only care about these subsystem */
enum SUBSYS_INDEX {
	CPU=0,
	MEMORY=1,
};

static char* sub_system[2] = {
	"cpu",
	"memory"
};

static FILE* log_file;

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s"
			" [-c cpu.shares 0-1024]"
			" [-m memory.limit_in_bytes ||k|K|m|M|g|G]"
			" command [arguments] \n", progname);
	fprintf(stderr, "Example: %s -c 100 -m 1G test test-param\n", progname);
	exit(2);
}

static int create_group_attach(int cpu_shares, const char* mem_limit)
{
	int ret = 0;
	int i;

	pid_t pid = getpid();
	pid_t ppid = getppid();

	/* cgroup related */
	struct cgroup* cgroup = NULL;
	char *control_path = NULL;
	struct cgroup_controller *cgc = NULL;
	char *path = NULL;
	char *controller = NULL;

	for (i=CPU; i<=MEMORY; i++) {
		controller = sub_system[i];

		/* Check Subsystem mounted */
		/*
		if (!cgroup_test_subsys_mounted(controller)) {
			fprintf(stderr, "%s not mounted\n", controller);
			ret = ECGROUPSUBSYSNOTMOUNTED;
			goto err;
		}*/

		/* Get parent path */
		ret = cgroup_get_current_controller_path(ppid, controller, &path);
		if (ret) {
			fprintf(stderr, "get parent pid(%d) path faild for controller %s: %s\n",
					ppid, controller, cgroup_strerror(ret));
			goto err;
		}
		else {
			/*
			 fprintf(stderr, "parent pid(%d) in controller %s, path %s\n",
					ppid, controller, path);
			*/
			ret = asprintf(&control_path, "%s/%d", path, pid);
			if (ret <= 0) {
				goto err;
			}

			/* create the new cgroup structure */
			cgroup = cgroup_new_cgroup(control_path);
			if (!cgroup) {
				fprintf(stderr, "cgroup_new_cgroup for %s failed\n", 
						control_path);
				ret = ECGFAIL;
				goto err;
			}

			cgc = cgroup_add_controller(cgroup, controller);
			if (!cgc) {
				fprintf(stderr, "cgroup_add_controller %s failed\n",
						controller);
				ret = ECGINVAL;
				goto err;
			}

			/* set values */
			if ((cpu_shares != 0) && (CPU == i)) {
				ret = cgroup_set_value_uint64(cgc, 
						"cpu.shares", (u_int64_t)cpu_shares);
				if (ret) {
					fprintf(stderr, 
						"set cpu.shares for %s failed: %s\n",
						control_path, cgroup_strerror(ret));
					goto err;
				}
			} else if ((mem_limit != NULL) && (MEMORY == i)) {
				ret = cgroup_set_value_string(cgc, 
						"memory.limit_in_bytes", mem_limit);
				if (ret) {
					fprintf(stderr, 
						"set memory.limit_in_bytes for %s failed: %s\n",
						control_path, cgroup_strerror(ret));
					goto err;
				}
			}

			ret = cgroup_set_value_bool(cgc, "notify_on_release", 1);
			if (ret) {
				fprintf(stderr, "set notify_on_release for %s failed: %s\n",
						control_path, cgroup_strerror(ret));
				goto err;
			}

			/* all variables set so create cgroup */
			ret = cgroup_create_cgroup(cgroup, 0);
			if (ret) {
				fprintf(stderr,	"can't create cgroup %s?: %s\n",
						controller, cgroup_strerror(ret));
				goto err;
			}

			/* attach task */
			ret = cgroup_attach_task_pid(cgroup, pid);
			if (ret) {
				fprintf(stderr,	"cgroup attach pid(%d) failed: %s\n",
						pid, cgroup_strerror(ret));
				goto err;
			}

			free(path);
			path = NULL;
			free(control_path);
			control_path = NULL;
			cgroup_free(&cgroup);
		}
	}

	return 0;

err:
	if (path) {
		free(path);
		path = NULL;
	}

	if (control_path) {
		free(control_path);
		control_path = NULL;
	}

	if (cgroup) {
		cgroup_free(&cgroup);
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int c;
	uid_t uid;
	gid_t gid;
	pid_t pid;

	/* args related */
	int cpu_shares = 0;
	const char* mem_limit = NULL;

	if (argc < 2) {
		usage(argv[0]);
	}

	while ((c = getopt_long(argc, argv, "+c:m:h", longopts, NULL)) > 0) {
		switch (c) {
		case 'c':
			cpu_shares = atoi(optarg);
			if (cpu_shares <=0 || cpu_shares >1024) {
				fprintf(stderr, "invalid cpu_sharesage\n");
				usage(argv[0]);
			}
			break;
		case 'm':
			mem_limit = optarg;
			break;
		case 'h':
			usage(argv[0]);
			break;
		default:
			fprintf(stderr, "Invalid command line option\n");
			usage(argv[0]);
			break;
		}
	}

	/* Executable name */
	if (!argv[optind]) {
		fprintf(stderr, "No command specified\n");
		return -1;
	}

	/*
	fprintf(stderr, "cpu: %d, mem: %s,"
			"command: %s\n", 
			cpu_shares, mem_limit, argv[optind]);
	*/

	/* Initialize libcg */
	ret = cgroup_init();
	if (ret) {
		fprintf(stderr, "libcgroup initialization failed: %s\n",
			cgroup_strerror(ret));
		return -1;
	}

	/* copy from cgexec, interact with daemon process */
	uid = getuid();
	gid = getgid();
	pid = getpid();

	/* tell daemon process: 
	   DON'T change the group for current & child process 
	   I'll control it myself */
	ret = cgroup_register_unchanged_process(pid, CGROUP_DAEMON_UNCHANGE_CHILDREN);
	if (ret) {
		fprintf(stderr, "registration of process failed\n");
		return -1;
	}

	ret = create_group_attach(cpu_shares, mem_limit);
	if (ret) {
		fprintf(stderr, "create_group_attach failed: %s\n",
			cgroup_strerror(ret));
		return -1;
	}

	/*
	 * 'cgexec' command file needs the root privilege for executing
	 * a cgroup_register_unchanged_process() by using unix domain
	 * socket, and an euid/egid should be changed to the executing user
	 * from a root user.
	 */
	if (setresuid(uid, uid, uid)) {
		fprintf(stderr, "setresuid %s", strerror(errno));
		return -1;
	}

	ret = setresgid(gid, gid, gid);
	if (ret < 0) {
		fprintf(stderr, "setsid return error: %s\n",
				strerror(errno));
		return -1;
	}
	
	/* Now exec the new process */
	ret = execvp(argv[optind], &argv[optind]);
	if (ret == -1) {
		fprintf(stderr, "execvp %s", strerror(errno));
		return -1;
	}

	return 0;
}
