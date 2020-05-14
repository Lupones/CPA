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

#pragma once


#include <map>
#include <vector>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include "cat-linux.hpp"
#include "common.hpp"
#include "throw-with-trace.hpp"


namespace mi = boost::multi_index;

double get_clos_pid(pid_t pid,std::shared_ptr<CAT> cat);
double get_mask_pid(pid_t pid,std::shared_ptr<CAT> cat);
double get_num_ways_pid(pid_t pid,std::shared_ptr<CAT> cat);

struct perf_evlist;

struct Counter
{
	int id = 0;
	std::string name = "";
	double value = 0;
	std::string unit = "";
	bool snapshot = false;
	uint64_t enabled = 0;
	uint64_t running = 0;

	Counter() = default;
	Counter(int _id, const std::string &_name, double _value, const std::string &_unit, bool _snapshot, uint64_t _enabled, uint64_t _running) :
			id(_id), name(_name), value(_value), unit(_unit), snapshot(_snapshot), enabled(_enabled), running(_running) {};
	bool operator<(const Counter &c) const {return id < c.id;}
};

struct by_id {};
struct by_name {};
typedef mi::multi_index_container<
	Counter,
	mi::indexed_by<
		// sort by Counter::operator<
		mi::ordered_unique<mi::tag<by_id>, mi::identity<Counter> >,

		// sort by less<string> on name
		mi::ordered_unique<
			mi::tag<by_name>,
			mi::member<
				Counter,
				std::string,
				&Counter::name
			>
		>
	>
> counters_t;


class Perf
{
	const int max_num_events = 32;

	struct EventDesc
	{
		std::vector<struct perf_evlist*> groups;

		EventDesc() = default;
		EventDesc(const std::vector<struct perf_evlist*> &_groups) :
				groups(_groups) {};
		void append(struct perf_evlist *ev_list) { groups.push_back(ev_list); }
	};

	std::map<pid_t, EventDesc> pid_events;
	bool initialized = false;

	public:

	Perf() = default;

	// Allow move members
	Perf(Perf&&) = default;
	Perf& operator=(Perf&&) = default;

	// Delete copy members
	Perf(const Perf&) = delete;
	Perf& operator=(const Perf&) = delete;

	~Perf() = default;


	void init();
	void clean();
	void clean(pid_t pid);
	void setup_events(pid_t pid, const std::vector<std::string> &groups);
	std::vector<counters_t> read_counters(pid_t pid,std::shared_ptr<CAT> cat);
	std::vector<std::vector<std::string>> get_names(pid_t pid);
	void enable_counters(pid_t pid);
	void disable_counters(pid_t pid);
	void print_counters(pid_t pid);
};


uint64_t read_max_ujoules_ram();
uint64_t read_max_ujoules_pkg();


