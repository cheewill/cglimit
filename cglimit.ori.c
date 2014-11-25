/*
 *
 * Authors:	
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
#include <libcgroup.h>
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

#include "tools-common.h"

static struct option longopts[] = {
	{"verbose", no_argument, NULL, 's'}, 
	{0, 0, 0, 0}
};

/* we only care about these subsystem */
enum SUBSYS_INDEX {
	CPU=0,
	CPUACCT=1,
	MEMORY=2,
};

static char* sub_system[3] = {
	"cpu",
	"cpuacct",
	"memory"
};

static FILE* log_file;

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s"
			" [-c cpu_percentage] [-m memory_limit]"
			" [-k oom_kill_mode] [-v/--verbose]"
			" [-f log_file] command [arguments] \n", progname);
	fprintf(stderr, "Usage: %s -h for help\n", progname);
	exit(2);
}

static int create_group_attach(int cpu_percent, const char* mem_limit, int kill_mode)
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
		if (!cgroup_test_subsys_mounted(controller)) {
			fprintf(stderr, "%s not mounted\n", controller);
			ret = ECGROUPSUBSYSNOTMOUNTED;
			goto err;
		}

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
			if ((cpu_percent != 0) && (CPU == i)) {
				ret = cgroup_set_value_uint64(cgc, "cpu.shares", 
						(u_int64_t)(cpu_percent*1024/10));
				if (ret) {
					fprintf(stderr, "set cpu.shares for %s failed: %s\n",
							control_path, cgroup_strerror(ret));
					goto err;
				}
			}
			else if ((mem_limit != NULL) && (MEMORY == i)) {
				ret = cgroup_set_value_string(cgc, "memory.limit_in_bytes",
						mem_limit);
				if (ret) {
					fprintf(stderr, "set memory.limit_in_bytes for %s failed: %s\n",
							control_path, cgroup_strerror(ret));
					goto err;
				}

				if (kill_mode != 0) {
					ret = cgroup_set_value_int64(cgc, "memory.kill_mode",
							kill_mode);
					if (ret) {
						fprintf(stderr, "set memory.kill_mode for %s failed: %s\n",
								control_path, cgroup_strerror(ret));
						goto err;
					}
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
				fprintf(stderr,	"can't create cgroup %s:%s: %s\n",
						controller, cgroup->name, cgroup_strerror(ret));
				goto err;
			}

			/* attach task */
			ret = cgroup_attach_task_pid(cgroup, pid);
			if (ret) {
				fprintf(stderr,	"cgroup attach pid(%d) failed: %s\n",
						pid, cgroup_strerror(ret));
				goto err;
			}
			/*
			ret = cgroup_change_cgroup_path(control_path,
					pid,
					controller);
			if (ret) {
				fprintf(stderr,
						"cgroup change of group failed\n");
				goto err;
			}
			*/

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

static int wait_child(pid_t child)
{
	int i;
	int ret = 0;
	int status;
	pid_t caught;

	struct cgroup *cgroup = NULL;
	char *path = NULL;
	char *controller = NULL;
	struct cgroup_controller *tcg = NULL;

	u_int64_t mem_max_usage = 0;
	u_int64_t cpu_usage = 0;
	char *cpu_stat = NULL;

	while ((caught = wait(&status)) != child)
	{
		if (caught == -1) {
			goto out;
		}
	}

	for (i=CPU; i<=MEMORY; i++) {
		controller = sub_system[i];

		/* Get current path */
		ret = cgroup_get_current_controller_path(getpid(), controller, &path);
		if (ret) {
			fprintf(stderr, "get current path faild for controller %s: %s\n",
					controller, cgroup_strerror(ret));
			goto out;
		}

		cgroup = cgroup_new_cgroup(path);
		if (!cgroup) {
			fprintf(stderr, "cgroup_new_cgroup for %s failed\n", 
					path);
			ret = ECGFAIL;
			goto out;
		}

		ret = cgroup_get_cgroup(cgroup);
		if (ret) {
			fprintf(stderr, "i=%d, cgroup_get_cgroup for %s failed, err: %s\n",
					i, path, cgroup_strerror(ret));
			goto out;
		}

		tcg = cgroup_get_controller(cgroup, controller);
		if (!tcg) {
			fprintf(stderr, "cgroup_get_controller %s failed for %s failed.\n",
					controller, cgroup->name);
			ret = ECGFAIL;
			goto out;
		}

		if (i == MEMORY) {
			ret = cgroup_get_value_uint64(tcg,
					"memory.max_usage_in_bytes", &mem_max_usage);
			if (ret) {
				fprintf(stderr, "get memory.max_usage_in_bytes from %s failed, err: %s\n",
						tcg->name, cgroup_strerror(ret));
				goto out;
			}
		}
		else if (i == CPUACCT) {
			ret = cgroup_get_value_uint64(tcg, 
					"cpuacct.usage", &cpu_usage);
			if (ret) {
				fprintf(stderr, "get cpuacct.usage from %s failed, err: %s\n",
						tcg->name, cgroup_strerror(ret));
				goto out;
			}

			ret = cgroup_get_value_string(tcg,
					"cpuacct.stat", &cpu_stat);
			if (ret) {
				fprintf(stderr, "get cpuacct.stat from %s failed, err: %s\n",
						tcg->name, cgroup_strerror(ret));
				goto out;
			}
		}

		free(path);
		path = NULL;
		cgroup_free(&cgroup);
	}

	fprintf(log_file, "memory.max_usage_in_bytes: %lu\n"
			"cpuacct.usage (ns): %lu\n"
			"cpuacct.stat (10ms): \n"
			"%s\n", 
			mem_max_usage, cpu_usage, cpu_stat);
	fflush(log_file);

out:
	if (path) {
		free(path);
		path = NULL;
	}

	if (cpu_stat) {
		free(cpu_stat);
		cpu_stat = NULL;
	}

	if (cgroup) {
		cgroup_free(&cgroup);
	}

	return ret;
}

static int run_cmd(char **cmd, int verbose)
{
	int ret = 0;
	pid_t child;
	sig_t interrupt_signal, quit_signal;

	if (0 == verbose) {
		/* Now exec the new process */
		ret = execvp(cmd[0], cmd);
		if (ret == -1) {
			fprintf(stderr, "%s\n", strerror(errno));
			return ret;
		}
	}
	else if (1 == verbose) {
		/* fork */
		child = fork();
		if (child < 0) {
			/* fork failed */
			fprintf(stderr, "fork failed.\n");
			return ret;
		}
		else if (0 == child) {
			/* child process */
			ret = execvp(cmd[0], cmd);
			if (ret == -1) {
				fprintf(stderr, "%s\n", strerror(errno));
				return ret;
			}
		}
		else {
			/* parent process */
			/* Have signals kill the child but not self (if possible).  */
			interrupt_signal = signal (SIGINT, SIG_IGN);
			quit_signal = signal (SIGQUIT, SIG_IGN);

			ret = wait_child(child);

			/* Re-enable signals.  */
			signal (SIGINT, interrupt_signal);
			signal (SIGQUIT, quit_signal);
		}
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
	int cpu_percent = 0;
	const char* mem_limit = NULL;
	int kill_mode = 0;
	int verbose = 0;

	if (argc < 2) {
		usage(argv[0]);
	}

	while ((c = getopt_long(argc, argv, "+c:m:k:vf:h", longopts, NULL)) > 0) {
		switch (c) {
		case 'c':
			cpu_percent = atoi(optarg);
			if (cpu_percent <=0 || cpu_percent >100) {
				fprintf(stderr, "invalid cpu_percentage\n");
				usage(argv[0]);
			}
			break;
		case 'm':
			mem_limit = optarg;
			break;
		case 'k':
			kill_mode = atoi(optarg);
			if (kill_mode != 0 && kill_mode != 1) {
				fprintf(stderr, "kill_mode can only be 0 or 1\n");
				usage(argv[0]);
			}
			break;
		case 'v':
			verbose = 1;
			log_file = stdout;
			break;
		case 'f':
			if (0 == strcmp(optarg, "-")) {
				log_file = stdout;
			}
			else {
				log_file = fopen(optarg, "a");
				if (!log_file) {
					fprintf(stderr, "Failed to open log file: %s,"
							" erorr: %s. Continuing anyway.\n",
							optarg, strerror(errno));
					log_file = stdout;
				}
			}
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
		ret = -1;
		goto err_exit;
	}

	/*
	fprintf(stderr, "cpu: %d, mem: %s, kill: %d, "
			"verbose: %d, log_file: %s\n", 
			cpu_percent, mem_limit, kill_mode, 
			verbose, log_file);
			*/

	/* Initialize libcg */
	ret = cgroup_init();
	if (ret) {
		fprintf(stderr, "libcgroup initialization failed: %s\n",
			cgroup_strerror(ret));
		ret = -2;
		goto err_exit;
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
		return ret;
	}

	ret = create_group_attach(cpu_percent, mem_limit, kill_mode);
	if (ret) {
		fprintf(stderr, "create_group_attach failed: %s\n",
			cgroup_strerror(ret));
		ret = -3;
		goto err_exit;
	}

	/* setsid: create a new session */
	pid = fork();

	if (pid < 0) {
		fprintf(stderr, "fork failed, error: %s\n",
				strerror(errno));
		goto err_exit;
	}
	else if (pid > 0) {
		exit(0);
	}
	else {
		if (seteuid(uid)) {
			fprintf(stderr, "%s", strerror(errno));
			ret = -1;
			goto err_exit;
		}

		ret = setsid();
		if (ret < 0) {
			fprintf(stderr, "setsid return error: %s\n",
					strerror(errno));
			ret = -4;
			goto err_exit;
		}

		ret = run_cmd(&argv[optind], verbose);
		if (ret) {
			fprintf(stderr, "run_cmd failed: %d\n", ret);
			ret = -5;
			goto err_exit;
		}

err_exit:
		if (log_file && log_file != stdout) {
			fclose(log_file);
		}
		exit(ret);
	}
}
