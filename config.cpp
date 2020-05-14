/*
Copyright (C) 2016  Vicent Selfa (viselol@disca.upv.es)
Copyright (C) 2020  Lucia Pons (lupones@disca.upv.es)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <iostream>
#include <map>

#include <boost/algorithm/string/replace.hpp>
#include <yaml-cpp/yaml.h>
#include <fmt/format.h>

#include "cat-linux-policy.hpp"
#include "config.hpp"
#include "log.hpp"


using std::vector;
using std::string;
using fmt::literals::operator""_format;


static std::shared_ptr<cat::policy::Base> config_read_cat_policy(const YAML::Node &config);
static vector<Cos> config_read_cos(const YAML::Node &config);
static tasklist_t config_read_tasks(const YAML::Node &config);
static YAML::Node merge(YAML::Node user, YAML::Node def);
static void config_check_required_fields(const YAML::Node &node, const std::vector<string> &required);
static void config_check_fields(const YAML::Node &node, const std::vector<string> &required, std::vector<string> allowed);


static
void config_check_required_fields(const YAML::Node &node, const std::vector<string> &required)
{
	assert(node.IsMap());

	// Check that required fields exist
	for (string field : required)
		if (!node[field])
			throw_with_trace(std::runtime_error("The node '{}' requires the field '{}'"_format(node.Scalar(), field)));
}


static
void config_check_fields(const YAML::Node &node, const std::vector<string> &required, std::vector<string> allowed)
{
	// Allowed is passed by value...
	allowed.insert(allowed.end(), required.begin(), required.end());

	assert(node.IsMap());

	config_check_required_fields(node, required);

	// Check that all the fields present are allowed
	for (const auto &n : node)
	{
		string field = n.first.Scalar();
		if (std::find(allowed.begin(), allowed.end(), field) == allowed.end())
			LOGWAR("Field '{}' is not allowed in the '{}' node"_format(field, node.Scalar()));
	}
}


static
std::shared_ptr<cat::policy::Base> config_read_cat_policy(const YAML::Node &config)
{
	YAML::Node policy = config["cat_policy"];

	if (!policy["kind"])
		throw_with_trace(std::runtime_error("The CAT policy needs a 'kind' field"));
	string kind = policy["kind"].as<string>();

	if (kind == "none")
		return std::make_shared<cat::policy::Base>();

	if (kind == "ca")
	{
		LOGINF("Using Critical-Aware (ca) CAT policy");

		// Check that required fields exist
		for (string field : {"every", "firstInterval"})
		{
			if (!policy[field])
				throw_with_trace(std::runtime_error("The '" + kind + "' CAT policy needs the '" + field + "' field"));
		}
		// Read fields
		uint64_t every = policy["every"].as<uint64_t>();
		uint64_t firstInterval = policy["firstInterval"].as<uint64_t>();

		return std::make_shared<cat::policy::CriticalAware>(every, firstInterval);
	}
 	else if (kind == "cpa")
	{
		LOGINF("Using Critical Phase-Aware (CPA) CAT policy");

		// Check that required fields exist
		for (string field : {"every", "firstInterval", "idleIntervals", "ipcLow", "ipcMedium", "icov", "hpkil3Limit"})
		{
			if (!policy[field])
				throw_with_trace(std::runtime_error("The '" + kind + "' CAT policy needs the '" + field + "' field"));
		}
		// Read fields
		uint64_t every = policy["every"].as<uint64_t>();
		uint64_t firstInterval = policy["firstInterval"].as<uint64_t>();
		uint64_t idleIntervals = policy["idleIntervals"].as<uint64_t>();
		double ipcLow = policy["ipcLow"].as<double>();
		double ipcMedium = policy["ipcMedium"].as<double>();
		double icov = policy["icov"].as<double>();
		double hpkil3Limit = policy["hpkil3Limit"].as<double>();

		return std::make_shared<cat::policy::CriticalPhaseAware>(every, firstInterval, idleIntervals, ipcMedium, ipcLow, icov, hpkil3Limit);
	}
	else if (kind == "np")
	{
		LOGINF("Using NoPart (np) CAT policy");

		// Check that required fields exist
		for (string field : {"every", "stats"})
		{
	       	if (!policy[field])
	           	throw_with_trace(std::runtime_error("The '" + kind + "' CAT policy needs the '" + field + "' field"));
		}
	    // Read fields
        uint64_t every = policy["every"].as<uint64_t>();
		std::string stats = policy["stats"].as<std::string>();

		return std::make_shared<cat::policy::NoPart>(every, stats);

	}
	else
		throw_with_trace(std::runtime_error("Unknown CAT policy: '" + kind + "'"));
}


static
vector<Cos> config_read_cos(const YAML::Node &config)
{
	YAML::Node cos_section = config["cos"];
	auto result = vector<Cos>();

	if (cos_section.Type() != YAML::NodeType::Sequence)
		throw_with_trace(std::runtime_error("In the config file, the cos section must contain a sequence"));

	for (size_t i = 0; i < cos_section.size(); i++)
	{
		const auto &cos = cos_section[i];

		// Schematas are mandatory
		if (!cos["schemata"])
			throw_with_trace(std::runtime_error("Each cos must have an schemata"));
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


static
tasklist_t config_read_tasks(const YAML::Node &config)
{
	YAML::Node tasks = config["tasks"];
	auto result = tasklist_t();
	vector<string> required;
	vector<string> allowed;
	for (size_t i = 0; i < tasks.size(); i++)
	{
		required = {"app"};
		allowed  = {"max_instr", "max_restarts", "define", "initial_clos", "cpus", "batch"};
		config_check_fields(tasks[i], required, allowed);

		if (!tasks[i]["app"])
			throw_with_trace(std::runtime_error("Each task must have an app dictionary with at least the key 'cmd', and optionally the keys 'stdout', 'stdin', 'stderr', 'skel' and 'max_instr'"));

		const auto &app = tasks[i]["app"];

		required = {"cmd"};
		allowed  = {"name", "skel", "stdin", "stdout", "stderr"};
		config_check_fields(app, required, allowed);

		// Commandline and name
		if (!app["cmd"])
			throw_with_trace(std::runtime_error("Each task must have a cmd"));
		string cmd = app["cmd"].as<string>();

		// Name defaults to the name of the executable if not provided
		string name = app["name"] ? app["name"].as<string>() : extract_executable_name(cmd);

		// Dir containing files to copy to rundir
		vector<string> skel = {""};
		if (app["skel"])
		{
			if (app["skel"].IsSequence())
				skel = app["skel"].as<vector<string>>();
			else
				skel = {app["skel"].as<string>()};
		}

		// Stdin/out/err redirection
		string output = app["stdout"] ? app["stdout"].as<string>() : "out";
		string input = app["stdin"] ? app["stdin"].as<string>() : "";
		string error = app["stderr"] ? app["stderr"].as<string>() : "err";

		// CPU affinity
		auto cpus = vector<uint32_t>();
		if (tasks[i]["cpus"])
		{
			auto node = tasks[i]["cpus"];
			assert(node.IsScalar() || node.IsSequence());
			if (node.IsScalar())
				cpus = {node.as<decltype (cpus)::value_type>()};
			else
				cpus = node.as<decltype(cpus)>();
		}
		else
		{
			cpus = sched::allowed_cpus();
		}

		// Initial CLOS
		uint32_t initial_clos = tasks[i]["initial_clos"] ? tasks[i]["initial_clos"].as<decltype(initial_clos)>() : 0;
		LOGINF("Initial CLOS {}"_format(initial_clos));

		// String to string replacement, a la C preprocesor, in the 'cmd' option
		auto vars = std::map<string, string>();
		if (tasks[i]["define"])
		{
			auto node = tasks[i]["define"];
			try
			{
				vars = node.as<decltype(vars)>();
			}
			catch(const std::exception &e)
			{
				throw_with_trace(std::runtime_error("The option 'define' should contain a string to string mapping"));
			}

			for (auto it = vars.begin(); it != vars.end(); ++it)
			{
				string key = it->first;
				string value = it->second;
				boost::replace_all(cmd, key, value);
			}
		}

		// Maximum number of instructions to execute
		auto max_instr = tasks[i]["max_instr"] ? tasks[i]["max_instr"].as<uint64_t>() : 0;
		uint32_t max_restarts = tasks[i]["max_restarts"] ? tasks[i]["max_restarts"].as<decltype(max_restarts)>() : std::numeric_limits<decltype(max_restarts)>::max() ;

		bool batch = tasks[i]["batch"] ? tasks[i]["batch"].as<bool>() : false;

		result.push_back(std::make_shared<Task>(name, cmd, initial_clos, cpus, output, input, error, skel, max_instr, max_restarts, batch));
	}
	return result;
}


static
YAML::Node merge(YAML::Node user, YAML::Node def)
{
	if (user.Type() == YAML::NodeType::Map && def.Type() == YAML::NodeType::Map)
	{
		for (auto it = def.begin(); it != def.end(); ++it)
		{
			std::string key = it->first.Scalar();
			YAML::Node value = it->second;

			if (!user[key])
				user[key] = value;
			else
				user[key] = merge(user[key], value);
		}
	}
	return user;
}


static
sched::ptr_t config_read_sched(const YAML::Node &config)
{
	if (!config["sched"])
		return std::make_shared<sched::Base>();

	const auto &sched = config["sched"];

	vector<string> required;
	vector<string> allowed;

	required = {"kind"};
	allowed  = {"allowed_cpus", "every"};

	// Check minimum required fields
	config_check_required_fields(sched, required);

	string kind                   = sched["kind"].as<string>();
	vector<uint32_t> allowed_cpus = sched["allowed_cpus"] ?
			sched["allowed_cpus"].as<decltype(allowed_cpus)>() :
			sched::allowed_cpus(); // All the allowed cpus for this process according to Linux
	uint32_t every = sched["every"] ? sched["every"].as<decltype(every)>() : 1;

	if (kind == "linux")
	{
		if (every != 1)
			LOGDEB("The Linux scheduler ingrores the 'every' option");
		config_check_fields(sched, required, allowed);
		return std::make_shared<sched::Base>(every, allowed_cpus);
	}

	throw_with_trace(std::runtime_error("Invalid sched kind '{}'"_format(kind)));
}


static
void config_read_cmd_options(const YAML::Node &config, CmdOptions &cmd_options)
{
	if (!config["cmd"])
		return;

	const auto &cmd = config["cmd"];

	vector<string> required;
	vector<string> allowed;

	required = {};
	allowed  = {"ti", "mi", "event", "cpu-affinity", "cat-impl"};

	// Check minimum required fields
	config_check_fields(cmd, required, allowed);

	if (cmd["ti"])
		cmd_options.ti = cmd["ti"].as<decltype(cmd_options.ti)>();
	if (cmd["mi"])
		cmd_options.mi = cmd["mi"].as<decltype(cmd_options.mi)>();
	if (cmd["event"])
		cmd_options.event = cmd["event"].as<decltype(cmd_options.event)>();
	if (cmd["cpu-affinity"])
		cmd_options.cpu_affinity = cmd["cpu-affinity"].as<decltype(cmd_options.cpu_affinity)>();
	if (cmd["cat-impl"])
		cmd_options.cat_impl = cmd["cat-impl"].as<decltype(cmd_options.cat_impl)>();
}


void config_read(const string &path, const string &overlay, CmdOptions &cmd_options, tasklist_t &tasklist, vector<Cos> &coslist, std::shared_ptr<cat::policy::Base> &catpol, sched::ptr_t &sched)
{
	// The message outputed by YAML is not clear enough, so we test first
	std::ifstream f(path);
	if (!f.good())
		throw_with_trace(std::runtime_error("File doesn't exist or is not readable"));

	YAML::Node config = YAML::LoadFile(path);

	if (overlay != "")
	{
		YAML::Node over = YAML::Load(overlay);
		config = merge(over, config);
	}

	// Read initial CAT config
	if (config["cos"])
		coslist = config_read_cos(config);

	// Read CAT policy
	if (config["cat_policy"])
		catpol = config_read_cat_policy(config);

	// Read tasks into objects
	if (config["tasks"])
		tasklist = config_read_tasks(config);

	// Check that all COS (but 0) have cpus or tasks assigned
	for (size_t i = 1; i < coslist.size(); i++)
	{
		const auto &cos = coslist[i];
		if (cos.cpus.empty())
			std::cerr << "Warning: COS " + std::to_string(i) + " has no assigned CPUs" << std::endl;
	}

	// Read scheduler
	sched = config_read_sched(config);

	// Read general config
	config_read_cmd_options(config, cmd_options);
}
