/*
Copyright (C) 2016  Vicent Selfa (viselol@disca.upv.es)
Copyright (C) 2020 Lucia Pons (lupones@disca.upv.es)

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

#include <fmt/format.h>

extern "C"
{
#include <libminiperf.h>
}

#include "common.hpp"
#include "events-perf.hpp"
#include "log.hpp"
#include "throw-with-trace.hpp"
#include "cat-linux.hpp"


using fmt::literals::operator""_format;

double read_energy_pkg();
double read_energy_ram();



double get_clos_pid(pid_t pid,std::shared_ptr<CAT> cat);
double get_mask_pid(pid_t pid,std::shared_ptr<CAT> cat);
double get_num_ways_pid(pid_t pid,std::shared_ptr<CAT> cat);

double get_clos_pid(pid_t pid,std::shared_ptr<CAT> cat)
{
	auto ptr = std::dynamic_pointer_cast<CATLinux>(cat);
	return (double) ptr->get_clos_of_task(pid);
}

double get_mask_pid(pid_t pid,std::shared_ptr<CAT> cat)
{
	auto ptr = std::dynamic_pointer_cast<CATLinux>(cat);
	uint32_t clos = ptr->get_clos_of_task(pid);
	//LOGINF("get_mask_pid : {:#x}"_format(ptr->get_cbm(clos)));
	return (double) ptr->get_cbm(clos);
}

double get_num_ways_pid(pid_t pid,std::shared_ptr<CAT> cat)
{
	auto ptr = std::dynamic_pointer_cast<CATLinux>(cat);
	uint32_t clos = ptr->get_clos_of_task(pid);
	uint64_t n = __builtin_popcount(ptr->get_cbm(clos));
	//LOGINF("get_num_ways_pid : {}"_format(n));
    return (double) n;
}


void Perf::init()
{}


void Perf::clean()
{
	for (const auto &item : pid_events)
		for (const auto &evlist : item.second.groups)
			::clean(evlist);
}


void Perf::clean(pid_t pid)
{
	for (const auto &evlist : pid_events.at(pid).groups)
		::clean(evlist);
	pid_events.erase(pid);
}


void Perf::setup_events(pid_t pid, const std::vector<std::string> &groups)
{
	assert(pid >= 1);
	for (const auto &events : groups)
	{
		const auto evlist = ::setup_events(std::to_string(pid).c_str(), events.c_str());
		if (evlist == NULL)
			throw_with_trace(std::runtime_error("Could not setup events '{}'"_format(events)));
		if (::num_entries(evlist) >= max_num_events)
			throw_with_trace(std::runtime_error("Too many events"));
		pid_events[pid].append(evlist);
		::enable_counters(evlist);
	}
}


void Perf::enable_counters(pid_t pid)
{
	for (const auto &evlist : pid_events[pid].groups)
		::enable_counters(evlist);
}


void Perf::disable_counters(pid_t pid)
{
	for (const auto &evlist : pid_events[pid].groups)
		::disable_counters(evlist);
}


uint64_t read_max_ujoules_ram()
{
	// TODO: This needs improvement... i.e. consider more packages etc.
	auto fdata = open_ifstream("/sys/class/powercap/intel-rapl:0/intel-rapl:0:0/max_energy_range_uj");
	auto fname = open_ifstream("/sys/class/powercap/intel-rapl:0/intel-rapl:0:0/name");
	uint64_t data;

	fdata >> data;

	std::string name;
	fname >> name;

	assert(name == "dram");

	return data;
}


uint64_t read_max_ujoules_pkg()
{
	// TODO: This needs improvement... i.e. consider more packages etc.
	auto fdata = open_ifstream("/sys/class/powercap/intel-rapl:0/max_energy_range_uj");
	auto fname = open_ifstream("/sys/class/powercap/intel-rapl:0/name");
	uint64_t data;

	fdata >> data;

	std::string name;
	fname >> name;

	assert(name == "package-0");

	return data;
}


double read_energy_ram()
{
	// TODO: This needs improvement... i.e. consider more packages etc.
	auto fdata = open_ifstream("/sys/class/powercap/intel-rapl:0/intel-rapl:0:0/energy_uj");
	auto fname = open_ifstream("/sys/class/powercap/intel-rapl:0/intel-rapl:0:0/name");
	uint64_t data;

	fdata >> data;

	std::string name;
	fname >> name;

	LOGDEB("RAM energy: " << data);

	assert(name == "dram");

	return (double) data / 1E6; // Convert it to joules
}


double read_energy_pkg()
{
	// TODO: This needs improvement... i.e. consider more packages etc.
	auto fdata = open_ifstream("/sys/class/powercap/intel-rapl:0/energy_uj");
	auto fname = open_ifstream("/sys/class/powercap/intel-rapl:0/name");
	uint64_t data;

	fdata >> data;

	std::string name;
	fname >> name;

	LOGDEB("PKG energy: " << data);

	assert(name == "package-0");

	return (double) data / 1E6; // Convert it to joules
}




std::vector<counters_t> Perf::read_counters(pid_t pid,std::shared_ptr<CAT> cat)
{
	const char *names[max_num_events];
	double results[max_num_events];
	const char *units[max_num_events];
	bool snapshot[max_num_events];
	uint64_t enabled[max_num_events];
	uint64_t running[max_num_events];

	const auto epkg = "power/energy-pkg/";
	const auto eram = "power/energy-ram/";
	// LUCIA add entries for CLOS and CAT info
    const auto closnum = "clos_num";
    const auto numways = "num_ways";
    const auto maskhex = "clos_mask";

	auto result = std::vector<counters_t>();

	bool first = true;
	for (const auto &evlist : pid_events[pid].groups)
	{
		int n = ::num_entries(evlist);
		auto counters = counters_t();
		::read_counters(evlist, names, results, units, snapshot, enabled, running);
		int i;
		for (i = 0; i < n; i++)
		{
			assert(running[i] <= enabled[i]);
			counters.insert({i, names[i], results[i], units[i], snapshot[i], enabled[i], running[i]});
		}
		// Put energy measurements only in the first group
		if (first)
		{
			counters.insert({i++, epkg, read_energy_pkg(), "j", false, 1, 1});
			counters.insert({i++, eram, read_energy_ram(), "j", false, 1, 1});
			// LUCIA put values
			counters.insert({i++, closnum, get_clos_pid(pid,cat), "", true, 1, 1});
			counters.insert({i++, maskhex, get_mask_pid(pid,cat), "", true, 1, 1});
			counters.insert({i++, numways, get_num_ways_pid(pid,cat), "", true, 1, 1});

			first = false;
		}
		result.push_back(counters);
	}
	return result;
}


std::vector<std::vector<std::string>> Perf::get_names(pid_t pid)
{
	const char *names[max_num_events];
	auto r = std::vector<std::vector<std::string>>();

	const auto epkg = "power/energy-pkg/";
	const auto eram = "power/energy-ram/";

	// LUCIA add entries for CLOS and CAT info
	const auto closnum = "clos_num";
	const auto numways = "num_ways";
	const auto maskhex = "clos_mask";

	bool first = true;
	for (const auto &evlist : pid_events[pid].groups)
	{
		int n = ::num_entries(evlist);
		auto v = std::vector<std::string>();
		::get_names(evlist, names);
		for (int i = 0; i < n; i++)
			v.push_back(names[i]);
		// Put energy measurements only in the first group
		if (first)
		{
			v.push_back(epkg);
			v.push_back(eram);
			//LUCIA add CLOS fields
			v.push_back(closnum);
			v.push_back(numways);
			v.push_back(maskhex);
			first = false;
		}
		r.push_back(v);
	}
	return r;
}


void Perf::print_counters(pid_t pid)
{
	for (const auto &evlist : pid_events[pid].groups)
		::print_counters(evlist);
}
