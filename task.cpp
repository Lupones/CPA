#include <iomanip>
#include <iostream>
#include <queue>
#include <sstream>
#include <vector>

#include <sched.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <boost/filesystem.hpp>
#include <cxx-prettyprint/prettyprint.hpp>
#include <fmt/format.h>
#include <glib.h>

#include "log.hpp"
#include "task.hpp"
#include "throw-with-trace.hpp"


namespace acc = boost::accumulators;
namespace fs = boost::filesystem;

using std::to_string;
using std::string;
using std::cerr;
using std::endl;
using fmt::literals::operator""_format;


// Init static atribute
std::atomic<uint32_t> Task::ID(0);

uint32_t task_increase_ipc_count(Task &task)
{
	return task.ipc_phase_count++;
}

uint32_t task_increase_clos_change_count(Task &task)
{
	return task.clos_change_count++;
}


void tasks_set_rundirs(tasklist_t &tasklist, const std::string &rundir_base)
{
	for (size_t i = 0; i < tasklist.size(); i++)
	{
		auto &task = *tasklist[i];
		task.rundir = rundir_base + "/" + std::to_string(i) + "-" + task.name;
		if (fs::exists(task.rundir))
			throw_with_trace(std::runtime_error("The rundir '" + task.rundir + "' already exists"));
	}
}


const task_ptr_t& tasks_find(const tasklist_t &tasklist, uint32_t id)
{
	const auto &it = std::find_if(tasklist.begin(), tasklist.end(), [id](const auto &t){return id == t->id;});
	if (it == tasklist.end())
		throw_with_trace(std::runtime_error("Task with id {} not foud"_format(id)));
	else
		return *it;
}


void task_create_rundir(const Task &task)
{
	if (!fs::create_directories(task.rundir))
		throw_with_trace(std::runtime_error("Could not create rundir directory " + task.rundir));

	// Copy to the rundir the contents of all the skel dirs
	for (const auto &skel : task.skel)
		if (skel != "")
			dir_copy_contents(skel, task.rundir);
}


void task_remove_rundir(const Task &task)
{
	fs::remove_all(task.rundir);
}


// Pause task
void task_pause(const Task &task)
{
	pid_t pid = task.pid;
	int status = 0;

	if (pid <= 1)
		throw_with_trace(std::runtime_error("Tried to send SIGSTOP to pid " + to_string(pid) + ", check for bugs"));

	kill(pid, SIGSTOP); // Stop child process
	if (waitpid(pid, &status, WUNTRACED) != pid) // Wait until it stops
		throw_with_trace(std::runtime_error("Error in waitpid for command '{}' with pid {}"_format(task.name, task.pid)));

	if (WIFEXITED(status))
		throw_with_trace(std::runtime_error("Command '" + task.cmd + "' with pid " + to_string(pid) + " exited unexpectedly with status " + to_string(WEXITSTATUS(status))));
}


// Pause multiple tasks
void tasks_pause(tasklist_t &tasklist)
{
	for (const auto &task : tasklist)
		kill(task->pid, SIGSTOP); // Stop process

	for (const auto &task : tasklist)
	{
		pid_t pid = task->pid;
		int status = 0;

		if (pid <= 1)
			throw_with_trace(std::runtime_error("Tried to send SIGSTOP to pid " + to_string(pid) + ", check for bugs"));

		if (waitpid(pid, &status, WUNTRACED) != pid) // Wait until it stops
			throw_with_trace(std::runtime_error("Error in waitpid for command '{}' with pid {}"_format(task->name, task->pid)));

		if (WIFEXITED(status))
		{
			if (status == 0)
			{
				LOGWAR("Task {}:{} with pid {} exited with status '{}'"_format(task->id, task->name, task->pid, status));
				task->completed++;
				task->set_status(Task::Status::exited);
			}
			else
			{
				throw_with_trace(std::runtime_error("Task {}:{} with pid {} exited unexpectedly with status '{}'"_format(task->id, task->name, task->pid, WEXITSTATUS(status))));
			}
		}
	}
}


void task_resume(const Task &task)
{
	pid_t pid = task.pid;
	int status;

	if (pid <= 1)
		throw_with_trace(std::runtime_error("Task {}:{}: tried to send SIGCONT to pid {}, check for bugs"_format(task.id, task.name, task.pid)));

	kill(pid, SIGCONT); // Resume process

	if (waitpid(pid, &status, WCONTINUED) != pid) // Ensure it resumed
		throw_with_trace(std::runtime_error("Error in waitpid for command '{}' with pid {}"_format(task.name, task.pid)));

	if (WIFEXITED(status))
		throw_with_trace(std::runtime_error("Command '" + task.cmd + "' with pid " + to_string(pid) + " exited unexpectedly with status " + to_string(WEXITSTATUS(status))));
}


// Resume multiple tasks
void tasks_resume(const tasklist_t &tasklist)
{
	for (const auto &task : tasklist)
		kill(task->pid, SIGCONT); // Resume process

	for (const auto &task : tasklist)
	{
		// The task has finished, is not running
		if (task->get_status() == Task::Status::exited)
			continue;

		pid_t pid = task->pid;
		int status;

		if (pid <= 1)
			throw_with_trace(std::runtime_error("Task {}:{}: tried to send SIGCONT to pid {}, check for bugs"_format(task->id, task->name, task->pid)));

		if (waitpid(pid, &status, WCONTINUED) != pid) // Ensure it resumed
			throw_with_trace(std::runtime_error("Error in waitpid for command '{}' with pid {}"_format(task->name, task->pid)));

		if (WIFEXITED(status))
			throw_with_trace(std::runtime_error("Task {}:{} with pid {} exited unexpectedly with status {}"_format(task->id, task->name, task->pid, WEXITSTATUS(status))));
	}
}



// Execute a task and immediately pause it
void task_execute(Task &task)
{
	int argc;
	char **argv;

	if (!g_shell_parse_argv(task.cmd.c_str(), &argc, &argv, NULL))
		throw_with_trace(std::runtime_error("Could not parse commandline '" + task.cmd + "'"));


	LOGDEB("Task cpu affinity: " << task.cpus);

	pid_t pid = fork();
	switch (pid) {
		// Child
		case 0:
		{
			setsid();

			// Set CPU affinity
			try
			{
				set_cpu_affinity(task.cpus);
			}
			catch (const std::exception &e)
			{
				cerr << "Could not set cpu affinity for task {}:{}: {}"_format(task.id, task.name, e.what()) << endl;
				exit(EXIT_FAILURE);
			}

			// Drop sudo privileges
			try
			{
				drop_privileges();
			}
			catch (const std::exception &e)
			{
				cerr << "Failed to drop privileges: " + string(e.what()) << endl;
			}

			// Create rundir with the necessary files and cd into it
			try
			{
				task_create_rundir(task);
			}
			catch (const std::exception &e)
			{
				cerr << "Could not create rundir: " + string(e.what()) << endl;
				exit(EXIT_FAILURE);
			}
			fs::current_path(task.rundir);

			// Redirect OUT/IN/ERR
			if (task.in != "")
			{
				fclose(stdin);
				if (fopen(task.in.c_str(), "r") == NULL)
				{
					cerr << "Failed to start program '" + task.cmd + "', could not open " + task.in << endl;
					exit(EXIT_FAILURE);
				}
			}
			if (task.out != "")
			{
				fclose(stdout);
				if (fopen(task.out.c_str(), "w") == NULL)
				{
					cerr << "Failed to start program '" + task.cmd + "', could not open " + task.out << endl;
					exit(EXIT_FAILURE);
				}
			}
			if (task.err != "")
			{
				fclose(stderr);
				if (fopen(task.err.c_str(), "w") == NULL)
				{
					cerr << "Failed to start program '" + task.cmd + "', could not open " + task.err << endl;
					exit(EXIT_FAILURE);
				}
			}

			// Exec
			execvp(argv[0], argv);

			// Should not reach this
			cerr << "Failed to start program '" + task.cmd + "'" << endl;
			exit(EXIT_FAILURE);
		}

			// Error
		case -1:
			throw_with_trace(std::runtime_error("Failed to start program '" + task.cmd + "'"));

			// Parent
		default:
			usleep(100); // Wait a bit, just in case
			task.pid = pid;
			LOGINF("Task {}:{} with pid {} has started"_format(task.id, task.name, task.pid));
			task_pause(task);
			g_strfreev(argv); // Free the memory allocated for argv
			break;
	}
}


void task_kill(Task &task)
{
	pid_t pid = task.pid;
	LOGINF("Killing task {}:{}"_format(task.id, task.name));
	if (pid > 1) // Never send kill to PID 0 or 1...
	{
		// Already dead
		if (task.get_status() == Task::Status::exited)
		{
			LOGINF("Task {}:{} with pid {} was already dead"_format(task.id, task.name, task.pid));
		}
		// Kill it
		else
		{
			if (kill(-pid, SIGKILL) < 0)
				throw_with_trace(std::runtime_error("Could not SIGKILL command '" + task.cmd + "' with pid " + to_string(pid) + ": " + strerror(errno)));
		}
		task.pid = 0;
	}
	else
	{
		throw_with_trace(std::runtime_error("Tried to kill pid " + to_string(pid) + ", check for bugs"));
	}
}


// Kill and restart a task
void task_restart(Task &task)
{
	LOGINF("Restarting task {}:{} {}/{}"_format(
			task.id, task.name, task.num_restarts + 1,
			task.max_restarts == std::numeric_limits<decltype(task.max_restarts)>::max() ?
				"inf" :
				std::to_string(task.max_restarts)));
	assert (task.get_status() == Task::Status::limit_reached || task.get_status() == Task::Status::exited);
	task.reset();
	task_remove_rundir(task);
	task_execute(task);
	task.num_restarts++;
}


std::vector<uint32_t> tasks_cores_used(const tasklist_t &tasklist)
{
	auto res = std::vector<uint32_t>();
	for (const auto &task : tasklist)
	{
		assert(task->cpus.size() > 0);
		if (task->cpus.size() != 1)
			LOGWAR("Ignoring all cpus but the first");
		res.push_back(task->cpus.front());
	}
	return res;
}


void task_restart_or_set_done(Task &task, cat_ptr_t cat, Perf &perf, const std::vector<std::string> &events)
{
	auto cat_linux = std::dynamic_pointer_cast<CATLinux>(cat);
	const auto status = task.get_status();
	uint32_t clos = -1U; // Invalid value

	if (cat_linux)
		clos = cat_linux->get_clos_of_task(task.pid);

	if (status == Task::Status::limit_reached || status == Task::Status::exited)
	{
		perf.clean(task.pid);
		if (status == Task::Status::limit_reached)
		{
			LOGINF("Task {}:{} limit reached, killing"_format(task.id, task.name));
			task_kill(task);
		}
		else if (status != Task::Status::exited)
		{
			throw_with_trace(std::runtime_error("Should not have reached this..."));
		}

		// Restart task if the maximum number of restarts has not been reached
		if (task.num_restarts < task.max_restarts)
		{
			if (cat_linux)
			{
				LOGDEB("Task {}:{} was in CLOS {}, ensure it still is after restart"_format(task.id, task.name, clos));
				assert(clos < cat->get_max_closids() && clos >= 0);
				task_restart(task);
				cat_linux->add_task(clos, task.pid);
			}
			else
			{
				task_restart(task);
			}
			perf.setup_events(task.pid, events);
		}
		else
		{
			task.set_status(Task::Status::done);
		}
	}
}


void task_stats_print_interval(const Task &t, uint64_t interval, std::ostream &out, const std::string &sep)
{
	int cpu_id = get_cpu_id(t.pid);
	out << interval << sep << std::setfill('0') << std::setw(2);
	out << t.id << "_" << t.name << sep << cpu_id << sep;

	// out << (t.max_instr ? (double) t.stats.get_current("instructions") / (double) t.max_instr : 0) << sep;
	double completed = t.max_instr ?
			(double) t.stats.sum("instructions") / (double) t.max_instr :
			NAN;
	out << completed << sep;
	out << t.stats.data_to_string_int(sep);
	out << std::endl;
}


void task_stats_print_total(const Task &t, uint64_t interval, std::ostream &out, const std::string &sep)
{
	int cpu_id = get_cpu_id(t.pid);
	out << interval << sep << std::setfill('0') << std::setw(2);
	out << t.id << "_" << t.name << sep << cpu_id << sep;
	double completed = t.max_instr ?
			(double) t.stats.sum("instructions") / (double) t.max_instr :
			NAN;
	out << completed << sep;
	out << t.stats.data_to_string_total(sep) << sep;
	out << t.ipc_phase_count << sep;
	out << t.clos_change_count;
	out << std::endl;
}


void task_stats_print_headers(const Task &t, std::ostream &out, const std::string &sep)
{
	out << "interval" << sep;
	out << "app" << sep;
	out << "CPU" << sep;
	out << "compl" << sep;
	out << t.stats.header_to_string(sep) << sep;
	out << "phase_changes" << sep;
	out << "CLOS_changes";
	out << std::endl;
}


void tasks_map_to_initial_clos(tasklist_t &tasklist, const std::shared_ptr<CATLinux> &cat)
{
	// Mapping a task to a CLOS requires Linux CAT, it is not supported by Intel CAT.
	// Therefore, if the feature is used, we have to check that the pointer is valid.
	bool initial_clos_used = false;
	for (const auto &task : tasklist)
	{
		if (task->initial_clos)
		{
			initial_clos_used = true;
			break;
		}
	}

	if (!initial_clos_used)
		return;

	if (!cat)
		throw_with_trace(std::runtime_error("Invalid CAT pointer: Ensure that you are using the Linux CAT implementation"));

	for (const auto &task : tasklist)
	{
		LOGINF("Map task {}:{} with PID {} to CLOS {}"_format(task->id, task->name, task->pid, task->initial_clos));
		cat->add_task(task->initial_clos, task->pid);
	}
}


bool task_exited(const Task &task)
{
	int status = 0;
	int ret = waitpid(task.pid, &status, WNOHANG);
	switch (ret)
	{
		case 0:
			return false;
		case -1:
			throw_with_trace(std::runtime_error("Task {} ({}) with pid {}: error in waitpid"_format(task.id, task.name, task.pid)));
		default:
			if (ret != task.pid)
				throw_with_trace(std::runtime_error("Task {} ({}) with pid {}: strange error in waitpid"_format(task.id, task.name, task.pid)));
			break;
	}

	if (WIFEXITED(status))
	{
		if (WEXITSTATUS(status) != 0)
			throw_with_trace(std::runtime_error("Task {} ({}) with pid {} exited unexpectedly with status {}"_format(task.id, task.name, task.pid, WEXITSTATUS(status))));
		return true;
	}
	return false;
}


const std::string Task::status_to_str(const Task::Status& s)
{
	switch(s)
	{
		case Status::runnable:
			return "runnable";
		case Status::limit_reached:
			return "limit_reached";
		case Status::exited:
			return "exited";
		case Status::done:
			return "done";
	}
	throw_with_trace(std::runtime_error("Unknown status, should not reach this"));
}


const std::string Task::status_to_str() const
{
	return status_to_str(status);
}


const Task::Status& Task::get_status() const
{
	return status;
};


void Task::set_status(const Task::Status &new_status)
{
	LOGDEB("Task {}:{} changes its status from {} to {}"_format(id, name, status_to_str(), status_to_str(new_status)));
	status = new_status;
};


// Reset flags
void Task::reset()
{
	stats.reset_counters();
	set_status(Status::runnable);
}
