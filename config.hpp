/*
Copyright (C) 2016  Vicent Selfa (viselol@disca.upv.es)

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

#include <cstdint>
#include <memory>
#include <vector>

#include "cat-policy.hpp"
#include "task.hpp"
#include "sched.hpp"


struct Cos
{
	uint64_t mask;              // Ways assigned mask
	std::vector<uint32_t> cpus; // Associated CPUs

	Cos(uint64_t _mask, const std::vector<uint32_t> &_cpus = {}) : mask(_mask), cpus(_cpus) {}
};


// Commandline options that can be setted using the config file
struct CmdOptions
{
		double                   ti           = 1; // Time interval
		uint32_t                 mi           = std::numeric_limits<uint32_t>::max(); // Max number of intervals
		std::vector<std::string> event        = {"ref-cycles", "instructions"}; // Events to monitor
		std::vector<uint32_t>    cpu_affinity = {}; // CPUs to pin the manager to
		std::string              cat_impl     = "linux"; // Linux or Intel implementation
};


void config_read(const std::string &path, const std::string &overlay, CmdOptions &cmd_options, tasklist_t &tasklist, std::vector<Cos> &coslist, std::shared_ptr<cat::policy::Base> &catpol, sched::ptr_t &sched);
