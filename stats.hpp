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
#include <map>
#include <ostream>

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/rolling_mean.hpp>
#include <boost/accumulators/statistics/rolling_window.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/stats.hpp>
#include <boost/accumulators/statistics/variance.hpp>

#include "accum-last.hpp"
#include "events-perf.hpp"


class Stats
{
	// Declare the 'accum_t' typedef
	#define ACC boost::accumulators
	typedef ACC::accumulator_set <
		double,
		ACC::stats <
			ACC::tag::last,
			ACC::tag::sum,
			ACC::tag::mean,
			ACC::tag::variance,
			ACC::tag::rolling_mean>> accum_t;
	#undef ACC

	// Set to true when the 'init' method is called
	bool initialized = false;

	// Times that the 'accum' method has been called
	uint64_t counter = 0;

	// Last and current counter values that have been passed to the 'accum' method
	counters_t cbak; // Only for the names and properties of the counters after a reset
	counters_t clast;
	counters_t ccurr;

	// Vectors with lambdas that compute derived stats
	std::vector<
		std::pair<
			std::string,
			std::function<double()>
		>
	> derived_metrics_int, derived_metrics_total;

	// Vector with the names of the counters that will be accumulated
	std::vector<std::string> names;

	std::string data_to_string(const std::string &sep, bool force_snapshot) const;

	public:

	std::map<std::string, accum_t> events;

	Stats() = default;
	Stats(const std::vector<std::string> &counters);

	void init(const std::vector<std::string> &counters);
	void init_derived_metrics_total(const std::vector<std::string> &counters);
	void init_derived_metrics_int(const std::vector<std::string> &counters);
	Stats& accum(const counters_t &c);

	void reset_counters();

	double get_current(const std::string &name) const;

	// sum of accumulated values
	double sum(const std::string &name) const;
	// Last accumulated value into the counter
	double last(const std::string &name) const;

	std::string header_to_string(const std::string &sep) const;
	std::string data_to_string_int(const std::string &sep) const;
	std::string data_to_string_total(const std::string &sep) const;
	std::string double2hexstr(double x) const;
};
