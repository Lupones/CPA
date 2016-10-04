#include <iostream>
#include <chrono>
#include <thread>

#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <boost/program_options.hpp>
#include <glib.h>
#include <yaml-cpp/yaml.h>

#include "cat-intel.hpp"
#include "common.hpp"
#include "manager_pcm.hpp"


namespace po = boost::program_options;
namespace chr = std::chrono;

using std::string;
using std::to_string;
using std::vector;
using std::this_thread::sleep_for;
using std::cout;
using std::cerr;
using std::endl;


struct Cos
{
	uint64_t mask;         // Ways assigned mask
	vector<uint32_t> cpus; // Associated CPUs

	Cos(uint64_t mask, vector<uint32_t> cpus = {}) : mask(mask), cpus(cpus){}
};


struct Task
{
	string cmd;
	vector<int> cpus; // Allowed cpus
	int pid;          // Set after executing the task

	Task(string cmd, vector<int> cpus, int pid = 0) : cmd(cmd), cpus(cpus), pid(pid) {}
};


vector<Cos> config_read_cos(const YAML::Node &config)
{
	YAML::Node cos_section = config["cos"];
	auto result = vector<Cos>();

	if (cos_section.Type() != YAML::NodeType::Sequence)
		throw std::runtime_error("In the config file, the cos section must contain a sequence");

	for (size_t i = 0; i < cos_section.size(); i++)
	{
		const auto &cos = cos_section[i];

		// Schematas are mandatory
		if (!cos["schemata"])
			throw std::runtime_error("Each cos must have an schemata");
		auto mask = cos["schemata"].as<uint64_t>();

		// CPUs are not mandatory, but note that COS 0 will have all the CPUs by defect
		auto cpus = vector<uint32_t>();
		if (cos["cpus"])
		{
			auto cpulist = cos["cpus"];
			for (auto it = cpulist.begin(); it != cpulist.end(); it++)
			{
				int cpu = it->as<int>();
				cpus.push_back(cpu);
			}
		}

		result.push_back(Cos(mask, cpus));
	}

	return result;
}


vector<Task> config_read_tasks(const YAML::Node &config)
{
	YAML::Node tasks = config["tasks"];
	auto result = vector<Task>();
	for (size_t i = 0; i < tasks.size(); i++)
	{
		// Commandline
		if (!tasks[i]["cmd"])
			throw std::runtime_error("Each task must have a cmd");
		string cmd = tasks[i]["cmd"].as<string>();

		// CPUS
		auto cpus = vector<int>(); // Default, no affinity
		if (tasks[i]["cpus"])
		{
			auto cpulist = tasks[i]["cpus"];
			for (auto it = cpulist.begin(); it != cpulist.end(); it++)
			{
				int cpu = it->as<int>();
				cpus.push_back(cpu);
			}
		}

		result.push_back(Task(cmd, cpus));
	}
	return result;
}


CAT cat_setup(const vector<Cos> &coslist, bool auto_reset)
{
	auto cat = CAT(auto_reset); // If auto_reset is set CAT is reseted before and after execution
	cat.init();

	for (size_t i = 0; i < coslist.size(); i++)
	{
		const auto &cos = coslist[i];
		cat.set_cos_mask(i, cos.mask);
		for (const auto &cpu : cos.cpus)
			cat.set_cos_cpu(i, cpu);
	}

	return cat;
}


// Pause task
void task_pause(const Task &task)
{
	int pid = task.pid;
	int status;

	if (pid <= 1)
		throw std::runtime_error("Tried to send SIGSTOP to pid " + to_string(pid) + ", check for bugs");

	kill(pid, SIGSTOP); // Stop child process
	waitpid(pid, &status, WUNTRACED); // Wait until it stops
	if (WIFEXITED(status))
		throw std::runtime_error("Command '" + task.cmd + "' with pid " + to_string(pid) + " exited unexpectedly with status " + to_string(WEXITSTATUS(status)));
}


// Pause multiple tasks
void tasks_pause(const vector<Task> &tasklist)
{
	for (const auto &task : tasklist)
		kill(task.pid, SIGSTOP); // Stop process

	for (const auto &task : tasklist)
	{
		int pid = task.pid;
		int status;

		if (pid <= 1)
			throw std::runtime_error("Tried to send SIGSTOP to pid " + to_string(pid) + ", check for bugs");

		waitpid(pid, &status, WUNTRACED); // Ensure it stopt
		if (WIFEXITED(status))
			throw std::runtime_error("Command '" + task.cmd + "' with pid " + to_string(pid) + " exited unexpectedly with status " + to_string(WEXITSTATUS(status)));
	}
}


// Resume multiple tasks
void tasks_resume(const vector<Task> &tasklist)
{
	for (const auto &task : tasklist)
		kill(task.pid, SIGCONT); // Resume process

	for (const auto &task : tasklist)
	{
		int pid = task.pid;
		int status;

		if (pid <= 1)
			throw std::runtime_error("Tried to send SIGCONT to pid " + to_string(pid) + ", check for bugs");

		waitpid(pid, &status, WCONTINUED); // Ensure it resumed
		if (WIFEXITED(status))
			throw std::runtime_error("Command '" + task.cmd + "' with pid " + to_string(pid) + " exited unexpectedly with status " + to_string(WEXITSTATUS(status)));
	}
}


// Drop sudo privileges
void drop_privileges()
{
	const char *uidstr = getenv("SUDO_UID");
	const char *gidstr = getenv("SUDO_GID");
	const char *userstr = getenv("SUDO_USER");

	if (!uidstr || !gidstr || !userstr)
		return;

	const uid_t uid = std::stol(uidstr);
	const gid_t gid = std::stol(gidstr);

	if (setgid(gid) < 0)
		throw std::runtime_error("Cannot change gid: " + string(strerror(errno)));

	if (initgroups(userstr, gid) < 0)
		throw std::runtime_error("Cannot change group access list: " + string(strerror(errno)));

	if (setuid(uid) < 0)
		throw std::runtime_error("Cannot change uid: " + string(strerror(errno)));
}


// Execute a task and immediately pause it
void task_execute(Task &task)
{
	int argc;
	char **argv;

	if (!g_shell_parse_argv(task.cmd.c_str(), &argc, &argv, NULL))
		throw std::runtime_error("Could not parse commandline '" + task.cmd + "'");

	pid_t pid = fork();
	switch (pid) {
		// Child
		case 0:
			{
				// Set CPU affinity
				cpu_set_t mask;
				CPU_ZERO(&mask);
				for (size_t i = 0; i < task.cpus.size(); i++)
					CPU_SET(task.cpus[i], &mask);
				sched_setaffinity(0, sizeof(mask), &mask);

				// Drop sudo privileges
				try
				{
					drop_privileges();
				}
				catch (const std::exception &e)
				{
					cerr << "Failed to drop privileges: " + string(e.what()) << endl;
				}

				// Redirect STDOUT to /dev/null
				int devnull = open("/dev/null", O_WRONLY);
				if (devnull < 0)
				{
					cerr << "Failed to start program '" + task.cmd + "', could not open /dev/null" << endl;
					exit(EXIT_FAILURE);
				}
				if (dup2(devnull, STDOUT_FILENO) < 0)
				{
					cerr << "Failed to start program '" + task.cmd + "', could not redirect STDOUT to /dev/null" << endl;
					exit(EXIT_FAILURE);
				}

				// Exec
				execvp(argv[0], argv);

				// Should not reach this
				cerr << "Failed to start program '" + task.cmd + "'" << endl;
				exit(EXIT_FAILURE);
			}

			// Error
		case -1:
			throw std::runtime_error("Failed to start program '" + task.cmd + "'");

			// Parent
		default:
			usleep(100); // Wait a bit, just in case
			task.pid = pid;
			task_pause(task);
			g_strfreev(argv); // Free the memory allocated for argv
			break;
	}
}


void task_kill(Task &task)
{
	int pid = task.pid;
	if (pid > 1) // Never send kill to PID 0 or 1...
	{
		if (kill(pid, SIGKILL) < 0)
			throw std::runtime_error("Could not SIGKILL command '" + task.cmd + "' with pid " + to_string(pid) + ": " + strerror(errno));
		task.pid = 0;
	}
	else
	{
		throw std::runtime_error("Tried to kill pid " + to_string(pid) + ", check for bugs");
	}
}


// Measure the time the passed callable object consumes
template<typename TimeT = chr::milliseconds>
struct measure
{
	template<typename F, typename ...Args>
		static typename TimeT::rep execution(F func, Args&&... args)
		{
			auto start = chr::system_clock::now();

			// Now call the function with all the parameters you need.
			func(std::forward<Args>(args)...);

			auto duration = chr::duration_cast<TimeT>
				(chr::system_clock::now() - start);

			return duration.count();
		}
};


void loop(vector<Task> tasklist, vector<Cos> coslist, CAT &cat, double time_int, double time_max, std::ostream &out)
{
	if (time_int <= 0)
		throw std::runtime_error("Interval time must be positive and greater than 0");
	if (time_max <= 0)
		throw std::runtime_error("Max time must be positive and greater than 0");

	int delay_ms = int(time_int * 1000);
	for (double time_elap = 0; time_elap < time_max; time_elap += time_int)
	{
		// Run for some time and pause
		tasks_resume(tasklist);
		pcm_before();
		sleep_for(chr::milliseconds(delay_ms));
		pcm_after(out);
		tasks_pause(tasklist);
	}
}


// Leave the machine in a consistent state
void clean(vector<Task> &tasklist, CAT &cat)
{
	cat.cleanup();
	pcm_clean();

	// Try to drop privileges before killing anything
	drop_privileges();

	for (auto &task : tasklist)
		task_kill(task);
}


void clean_and_die(vector<Task> &tasklist, CAT &cat)
{
	cerr << "--- PANIC, TRYING TO CLEAN ---" << endl;

	try
	{
		cat.reset();
	}
	catch (const std::exception &e)
	{
		cerr << "Could not reset CAT: " << e.what() << endl;
	}

	try
	{
		pcm_clean();
	}
	catch (const std::exception &e)
	{
		cerr << "Could not clean PCM: " << e.what() << endl;
	}

	// Try to drop privileges before killing anything
	drop_privileges();

	for (auto &task : tasklist)
	{
		try
		{
			if (task.pid > 0)
				task_kill(task);
		}
		catch (const std::exception &e)
		{
			cerr << "Could not kill task " << task.cmd << "with pid " << task.pid << ": " << e.what() << endl;
		}
	}

	exit(EXIT_FAILURE);
}


void config_read(const string &path, vector<Task> &tasklist, vector<Cos> &coslist)
{
	YAML::Node config = YAML::LoadFile(path);

	// Setup COS
	if (config["cos"])
		coslist = config_read_cos(config);

	// Read tasks into objects
	if (config["tasks"])
		tasklist = config_read_tasks(config);

	// Check that all COS (but 0) have cpus or tasks assigned
	for (size_t i = 1; i < coslist.size(); i++)
	{
		const auto &cos = coslist[i];
		if (cos.cpus.empty())
			cerr << "Warning: COS " + to_string(i) + " has no assigned CPUs" << endl;
	}
}


int main(int argc, char *argv[])
{
	po::options_description desc("Allowed options");
	desc.add_options()
		("help,h", "print usage message")
		("config,c", po::value<string>()->required(), "pathname for yaml config file")
		("output,o", po::value<string>(), "pathname for output")
		("ti", po::value<double>()->default_value(1), "time-int, duration in seconds of the time interval to sample performance counters.")
		("tm", po::value<double>()->default_value(std::numeric_limits<double>::max()), "time-max, maximum execution time in seconds, where execution time is computed adding all the intervals executed.")
		("event,e", po::value<vector<string>>()->composing()->multitoken()->required(), "optional list of custom events to monitor (up to 4)")
		("reset-cat", po::value<bool>()->default_value(true), "reset CAT config, before and after")
		// ("cores,c", po::value<vector<int>>()->composing()->multitoken(), "enable specific cores to output")
		;

	bool option_error = false;
	po::variables_map vm;
	try
	{
		// Parse the options without storing them in a map.
		po::parsed_options parsed_options = po::command_line_parser(argc, argv)
			.options(desc)
			.run();

		po::store(parsed_options, vm);
		po::notify(vm);
	}
	catch(const std::exception &e)
	{
		cerr << "Error: " << e.what() << "\n\n";
		option_error = true;
	}

	if (vm.count("help") || option_error)
	{
		cout << desc << endl;
		exit(EXIT_SUCCESS);
	}

	// Open output file if needed; if not, use cout
	auto file = std::ofstream();
	if (vm.count("output"))
		file = open_ofstream(vm["output"].as<string>());
	std::ostream &out = file.is_open() ? file : cout;

	// Read config
	auto tasklist = vector<Task>();
	auto coslist = vector<Cos>();
	string config_file;
	try
	{
		// Read config and set tasklist and coslist
		config_file = vm["config"].as<string>();
		config_read(config_file, tasklist, coslist);
	}
	catch(const std::exception &e)
	{
		cerr << "Error in config file '" + config_file + "': " << e.what() << endl;
		exit(EXIT_FAILURE);
	}

	auto cat = CAT();
	try
	{
		// Configure PCM
		pcm_setup(vm["event"].as<vector<string>>());

		// Configure CAT
		cat = cat_setup(coslist, vm["reset-cat"].as<bool>());

		// Execute and immediately pause tasks
		for (auto &task : tasklist)
			task_execute(task);

		// Start doing things
		loop(tasklist, coslist, cat, vm["ti"].as<double>(), vm["tm"].as<double>(), out);

		// Kill tasks, reset CAT, performance monitors, etc...
		clean(tasklist, cat);
	}
	catch(const std::exception &e)
	{
		cerr << "Error: " << e.what() << endl;
		clean_and_die(tasklist, cat);
	}
}
