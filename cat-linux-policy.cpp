/*
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

#include <algorithm>
#include <cmath>
#include <iostream>
#include <iterator>
#include <memory>
#include <tuple>

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/max.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/stats.hpp>
#include <boost/accumulators/statistics/variance.hpp>
#include <fmt/format.h>

#include "cat-linux-policy.hpp"
#include "log.hpp"

namespace cat
{
namespace policy
{


namespace acc = boost::accumulators;
using std::string;
using fmt::literals::operator""_format;

// varaible to assign tasks or cores to CLOS: task / cpu
const std::string CLOS_ADD = "task";

// No Part Policy
void NoPart::apply(uint64_t current_interval, const tasklist_t &tasklist)
{
	// Apply only when the amount of intervals specified has passed
	if (current_interval % every != 0)
		return;

	double ipcTotal = 0;

	LOGINF("CAT Policy name: NoPart");
	LOGINF("Using {} stats"_format(stats));

	for (const auto &task_ptr : tasklist)
	{
		const Task &task = *task_ptr;
		std::string taskName = task.name;

		double inst = 0, cycl = 0, ipc = -1;

		assert((stats == "total") | (stats == "interval"));

		if (stats == "total")
		{
			// Cycles and IPnC
			inst = task.stats.sum("instructions");
			cycl = task.stats.sum("cycles");
		}
		else if (stats == "interval")
		{
			// Cycles and IPnC
			inst = task.stats.last("instructions");
			cycl = task.stats.last("cycles");
		}

		ipc = inst / cycl;
		ipcTotal += ipc;
	}
}


// Auxiliar method of Critical Alone policy to reset configuration
void CriticalAware::reset_configuration(const tasklist_t &tasklist)
{
	// assign all tasks to CLOS 1
	if (CLOS_ADD == "task")
	{
		for (const auto &task_ptr : tasklist)
		{
			const Task &task = *task_ptr;
			pid_t taskPID = task.pid;
			LinuxBase::get_cat()->add_task(1, taskPID);
		}
	}
	else
	{
		// assign all cores to CLOS 1
		for (uint32_t c = 0; c < 8; c++)
		{
			LinuxBase::get_cat()->add_cpu(1, c);
		}
	}

	// change masks of CLOS to 0xfffff
	LinuxBase::get_cat()->set_cbm(1, 0xfffff);
	LinuxBase::get_cat()->set_cbm(2, 0xfffff);

	firstTime = 1;
	state = 0;
	expectedIPCtotal = 0;

	maskCrCLOS = 0xfffff;
	maskNonCrCLOS = 0xfffff;

	num_ways_CLOS_2 = 20;
	num_ways_CLOS_1 = 20;

	num_shared_ways = 0;

	idle = false;
	idle_count = IDLE_INTERVALS;

	LOGINF("Reset performed. Original configuration restored");
}

double CriticalAware::medianV(std::vector<pairD_t> &vec)
{
	double med;
	size_t size = vec.size();

	if (size % 2 == 0)
	{
		med = (std::get<1>(vec[size / 2 - 1]) + std::get<1>(vec[size / 2])) / 2;
	}
	else
	{
		med = std::get<1>(vec[size / 2]);
	}
	return med;
}

void CriticalAware::apply(uint64_t current_interval, const tasklist_t &tasklist)
{
	LOGINF("Current_interval = {}"_format(current_interval));
	// Apply only when the amount of intervals specified has passed
	if (current_interval % every != 0)
		return;

	// (Core, MPKI-L3) tuple
	auto v = std::vector<pairD_t>();
	auto v_ipc = std::vector<pairD_t>();
	auto v_l3_occup_mb = std::vector<pairD_t>();

	// Vector with current active tasks
	auto active_tasks = std::vector<pid_t>();

	auto outlier = std::vector<pair_t>();

	double ipcTotal = 0, mpkiL3Total = 0;
	// double missesL3Total = 0, instsTotal = 0;
	double ipc_CR = 0;
	double ipc_NCR = 0;
	double l3_occup_mb_total = 0;

	uint64_t newMaskNonCr, newMaskCr;

	// Number of critical apps found in the interval
	uint32_t critical_apps = 0;
	bool change_in_outliers = false;

	LOGINF("CAT Policy name: Critical-Aware");

	// Gather data
	for (const auto &task_ptr : tasklist)
	{
		const Task &task = *task_ptr;
		std::string taskName = task.name;
		pid_t taskPID = task.pid;
		uint32_t cpu = task.cpus.front();

		// stats per interval
		uint64_t l3_miss = task.stats.last("mem_load_uops_retired.l3_miss");
		uint64_t inst = task.stats.last("instructions");
		double ipc = task.stats.last("ipc");
		double l3_occup_mb = task.stats.last("intel_cqm/llc_occupancy/") / 1024 / 1024;

		l3_occup_mb_total += l3_occup_mb;

		double MPKIL3 = (double)(l3_miss * 1000) / (double)inst;

		// LOGINF("Task {}: MPKI_L3 = {}"_format(taskName,MPKIL3));
		LOGINF("Task {} ({}): IPC = {}, MPKI_L3 = {}, l3_occup_mb {}"_format(taskName, taskPID, ipc,
																			 MPKIL3, l3_occup_mb));
		v.push_back(std::make_pair(taskPID, MPKIL3));
		v_ipc.push_back(std::make_pair(taskPID, ipc));
		pid_CPU.push_back(std::make_pair(taskPID, cpu));
		active_tasks.push_back(taskPID);

		ipcTotal += ipc;
		mpkiL3Total += MPKIL3;
	}

	// Perform no further action if cache-warmup time has not passed
	if (current_interval < firstInterval)
		return;

	// Check if taskIsInCRCLOS holds only current tasks
	// aux = vector to store reset values
	auto aux = std::vector<pair_t>();
	for (const auto &item : taskIsInCRCLOS)
	{
		pid_t taskPID = std::get<0>(item);
		uint64_t CLOS_val = std::get<1>(item);
		if (std::find(active_tasks.begin(), active_tasks.end(), taskPID) == active_tasks.end())
		{
			LOGINF("TASK {} HAS BEEN RESTARTED "_format(taskPID));
			// Save task no longer active
			aux.push_back(std::make_pair(taskPID, CLOS_val));
		}
	}

	if (!aux.empty())
	{
		// Remove tasks no longer active from taskIsInCRCLOS
		for (const auto &item : aux)
		{
			pid_t taskPID = std::get<0>(item);
			auto it2 = std::find_if(
					taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
					[&taskPID](const auto &tuple) { return std::get<0>(tuple) == taskPID; });
			it2 = taskIsInCRCLOS.erase(it2);
		}
		aux.clear();

		// Add new active tasks to taskIsInCRCLOS
		for (const auto &item : active_tasks)
		{
			pid_t taskPID = item;
			auto it2 = std::find_if(
					taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
					[&taskPID](const auto &tuple) { return std::get<0>(tuple) == taskPID; });
			if (it2 == taskIsInCRCLOS.end())
			{
				// Check CLOS value of task
				uint64_t CLOS_val = LinuxBase::get_cat()->get_clos_of_task(taskPID);

				// Add new pair
				taskIsInCRCLOS.push_back(std::make_pair(taskPID, CLOS_val));
				LOGINF("RESTARTED TASK {} in CLOS {} HAS BEEN ADDED to taskIsInCRCLOS"_format(
						taskPID, CLOS_val));
			}
		}
	}

	// calculate total MPKIL3 mean of interval
	double meanMPKIL3Total = mpkiL3Total / tasklist.size();
	LOGINF("Total L3 occupation: {}"_format(l3_occup_mb_total));
	LOGINF("Mean MPKI_LLC_Total (/{}) = {}"_format(tasklist.size(), meanMPKIL3Total));

	// PROCESS DATA
	if (current_interval >= firstInterval)
	{
		// MAD = Median Absolute Value
		// 1. Sort in ascending order vector v
		// std::sort(v.begin(), v.end(), [](const std::tuple<pid_t, double> &left, const
		// std::tuple<pid_t, double> &right) {
		//		return std::get<1>(left) < std::get<1>(right);
		//});

		// 2. Find the median
		// double Mj = medianV(v);

		// 3. Subtract from each value the median
		// auto v_sub = v;
		// for (std::tuple<pid_t, double> &tup : v_sub)
		//{
		//	std::get<1>(tup) = fabs (std::get<1>(tup) - Mj);
		//}

		// 4. Sort in ascending order the new set of values
		// std::sort(v_sub.begin(), v_sub.end(), [](const std::tuple<pid_t, double> &left, const
		// std::tuple<pid_t, double> &right) {
		//	   return std::get<1>(left) < std::get<1>(right);
		//});

		// 5. Find the median
		// double Mi = medianV(v_sub);

		// 6. Multiply median by b (assume normal distribution)
		// double MAD = Mi * 1.4826;

		// 7. Calculate limit_outlier
		// double limit_outlier = Mj + 3*MAD;

		// MEAN AND STD LIMIT OUTLIER CALCULATION
		// accumulate value
		macc(meanMPKIL3Total);

		// calculate rolling mean
		mpkiL3Mean = acc::rolling_mean(macc);
		LOGINF("Rolling mean of MPKI-L3 at interval {} = {}"_format(current_interval, mpkiL3Mean));

		// calculate rolling std and limit of outlier
		stdmpkiL3Mean = std::sqrt(acc::rolling_variance(macc));
		LOGINF("stdMPKILLCmean = {}"_format(stdmpkiL3Mean));

		// calculate limit outlier
		double limit_outlier = mpkiL3Mean + 3 * stdmpkiL3Mean;
		LOGINF("limit_outlier = {}"_format(limit_outlier));


		pid_t pidTask;
		// Check if MPKI-L3 of each APP is 2 stds o more higher than the mean MPKI-L3
		for (const auto &item : v)
		{
			double MPKIL3Task = std::get<1>(item);
			pidTask = std::get<0>(item);
			int freqCritical = -1;
			double fractionCritical = 0;

			if (current_interval > firstInterval)
			{
				// Search for mi tuple and update the value
				auto it = frequencyCritical.find(pidTask);
				if (it != frequencyCritical.end())
				{
					freqCritical = it->second;
				}
				else
				{
					LOGINF("TASK RESTARTED --> INCLUDE IT AGAIN IN frequencyCritical");
					frequencyCritical[pidTask] = 0;
					freqCritical = 0;
				}
				assert(freqCritical >= 0);
				fractionCritical = freqCritical / (double)(current_interval - firstInterval);
				LOGINF("Fraction Critical ({} / {}) = {}"_format(
						freqCritical, (current_interval - firstInterval), fractionCritical));
			}


			if (MPKIL3Task >= limit_outlier)
			{
				LOGINF("The MPKI_LLC of task with pid {} is an outlier, since {} >= {}"_format(
						pidTask, MPKIL3Task, limit_outlier));
				outlier.push_back(std::make_pair(pidTask, 1));
				critical_apps = critical_apps + 1;

				// increment frequency critical
				frequencyCritical[pidTask]++;
			}
			else if (MPKIL3Task < limit_outlier && fractionCritical >= 0.5)
			{
				LOGINF("The MPKI_LLC of task with pid {} is NOT an outlier, since {} < {}"_format(
						pidTask, MPKIL3Task, limit_outlier));
				LOGINF("Fraction critical of {} is {} --> CRITICAL"_format(pidTask,
																		   fractionCritical));

				outlier.push_back(std::make_pair(pidTask, 1));
				critical_apps = critical_apps + 1;
			}
			else
			{
				// it's not a critical app
				LOGINF("The MPKI_LLC of task with pid {} is NOT an outlier, since {} < {}"_format(
						pidTask, MPKIL3Task, limit_outlier));
				outlier.push_back(std::make_pair(pidTask, 0));

				// initialize counter if it's the first interval
				if (current_interval == firstInterval)
				{
					frequencyCritical[pidTask] = 0;
				}
			}
		}

		LOGINF("critical_apps = {}"_format(critical_apps));

		// check CLOS are configured to the correct mask
		if (firstTime)
		{
			// set ways of CLOS 1 and 2
			switch (critical_apps)
			{
				case 1:
					// 1 critical app = 12cr10others
					maskCrCLOS = 0xfff00;
					num_ways_CLOS_2 = 12;
					maskNonCrCLOS = 0x003ff;
					num_ways_CLOS_1 = 10;
					state = 1;
					break;
				case 2:
					// 2 critical apps = 13cr9others
					maskCrCLOS = 0xfff80;
					num_ways_CLOS_2 = 13;
					maskNonCrCLOS = 0x001ff;
					num_ways_CLOS_1 = 9;
					state = 2;
					break;
				case 3:
					// 3 critical apps = 14cr8others
					maskCrCLOS = 0xfffc0;
					num_ways_CLOS_2 = 14;
					maskNonCrCLOS = 0x000ff;
					num_ways_CLOS_1 = 8;
					state = 3;
					break;
				default:
					// no critical apps or more than 3 = 20cr20others
					maskCrCLOS = 0xfffff;
					num_ways_CLOS_2 = 20;
					maskNonCrCLOS = 0xfffff;
					num_ways_CLOS_1 = 20;
					state = 4;
					break;
			} // close switch

			num_shared_ways = 2;
			LinuxBase::get_cat()->set_cbm(1, maskNonCrCLOS);
			LinuxBase::get_cat()->set_cbm(2, maskCrCLOS);

			LOGINF("COS 2 (CR) now has mask {:#x}"_format(maskCrCLOS));
			LOGINF("COS 1 (non-CR) now has mask {:#x}"_format(maskNonCrCLOS));


			firstTime = 0;
			// assign each core to its corresponding CLOS
			for (const auto &item : outlier)
			{
				pidTask = std::get<0>(item);
				uint32_t outlierValue = std::get<1>(item);

				auto it = std::find_if(v_ipc.begin(), v_ipc.end(), [&pidTask](const auto &tuple) {
					return std::get<0>(tuple) == pidTask;
				});
				double ipcTask = std::get<1>(*it);

				double cpuTask;
				if (CLOS_ADD == "cpu")
				{
					auto it1 = std::find_if(pid_CPU.begin(), pid_CPU.end(),
											[&pidTask](const auto &tuple) {
												return std::get<0>(tuple) == pidTask;
											});
					cpuTask = std::get<1>(*it1);
				}

				if (outlierValue)
				{
					if (CLOS_ADD == "cpu")
					{
						LinuxBase::get_cat()->add_cpu(2, cpuTask);
						LOGINF("Task in cpu {} assigned to CLOS 2"_format(cpuTask));
					}
					else
					{
						LinuxBase::get_cat()->add_task(2, pidTask);
						LOGINF("Task PID {} assigned to CLOS 2"_format(pidTask));
					}
					taskIsInCRCLOS.push_back(std::make_pair(pidTask, 2));

					ipc_CR += ipcTask;
				}
				else
				{
					if (CLOS_ADD == "cpu")
					{
						LinuxBase::get_cat()->add_cpu(1, cpuTask);
						LOGINF("Task in cpu {} assigned to CLOS 1"_format(cpuTask));
					}
					else
					{
						LinuxBase::get_cat()->add_task(1, pidTask);
						LOGINF("Task PID {} assigned to CLOS 1"_format(pidTask));
					}

					taskIsInCRCLOS.push_back(std::make_pair(pidTask, 1));
					ipc_NCR += ipcTask;
				}
			}
		}
		else
		{
			// check if there is a new critical app
			for (const auto &item : outlier)
			{

				pidTask = std::get<0>(item);
				uint32_t outlierValue = std::get<1>(item);

				auto it = std::find_if(v_ipc.begin(), v_ipc.end(), [&pidTask](const auto &tuple) {
					return std::get<0>(tuple) == pidTask;
				});
				double ipcTask = std::get<1>(*it);

				auto it2 = std::find_if(
						taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
						[&pidTask](const auto &tuple) { return std::get<0>(tuple) == pidTask; });
				uint64_t CLOSvalue = std::get<1>(*it2);
				assert((CLOSvalue == 1) | (CLOSvalue == 2));


				if (outlierValue && (CLOSvalue % 2 != 0))
				{
					LOGINF("There is a new critical app (outlier {}, current CLOS {})"_format(
							outlierValue, CLOSvalue));
					change_in_outliers = true;
				}
				else if (!outlierValue && (CLOSvalue == 2))
				{
					LOGINF("There is a critical app that is no longer critical)");
					change_in_outliers = true;
				}
				else if (outlierValue)
				{
					ipc_CR += ipcTask;
				}
				else
				{
					ipc_NCR += ipcTask;
				}
			}

			// reset configuration if there is a change in critical apps
			if (change_in_outliers)
			{
				taskIsInCRCLOS.clear();
				reset_configuration(tasklist);
			}
			else if (idle)
			{
				LOGINF("Idle interval {}"_format(idle_count));
				idle_count = idle_count - 1;
				if (idle_count == 0)
				{
					idle = false;
					idle_count = IDLE_INTERVALS;
				}
			}
			else if (!idle)
			{
				// if there is no new critical app, modify mask if not done previously
				if (critical_apps > 0 && critical_apps < 4)
				{
					LOGINF("IPC total = {}"_format(ipcTotal));
					LOGINF("Expected IPC total = {}"_format(expectedIPCtotal));

					double UP_limit_IPC = expectedIPCtotal * 1.04;
					double LOW_limit_IPC = expectedIPCtotal * 0.96;
					double NCR_limit_IPC = ipc_NCR_prev * 0.96;
					double CR_limit_IPC = ipc_CR_prev * 0.96;


					if (ipcTotal > UP_limit_IPC)
						LOGINF("New IPC is BETTER: IPCtotal {} > {}"_format(ipcTotal,
																			UP_limit_IPC));
					else if ((ipc_CR < CR_limit_IPC) && (ipc_NCR >= NCR_limit_IPC))
						LOGINF("WORSE CR IPC: CR {} < {} && NCR {} >= {}"_format(
								ipc_CR, CR_limit_IPC, ipc_NCR, NCR_limit_IPC));
					else if ((ipc_NCR < NCR_limit_IPC) && (ipc_CR >= CR_limit_IPC))
						LOGINF("WORSE NCR IPC: NCR {} < {} && CR {} >= {}"_format(
								ipc_NCR, NCR_limit_IPC, ipc_CR, CR_limit_IPC));
					else if ((ipc_CR < CR_limit_IPC) && (ipc_NCR < NCR_limit_IPC))
						LOGINF("BOTH IPCs are WORSE: CR {} < {} && NCR {} < {}"_format(
								ipc_CR, CR_limit_IPC, ipc_NCR, NCR_limit_IPC));
					else
						LOGINF("BOTH IPCs are EQUAL (NOT WORSE)");

					// transitions switch-case
					switch (state)
					{
						case 1:
						case 2:
						case 3:
							if (ipcTotal > UP_limit_IPC)
								idle = true;
							else if ((ipcTotal <= UP_limit_IPC) && (ipcTotal >= LOW_limit_IPC))
								state = 5;
							else if ((ipc_NCR < NCR_limit_IPC) && (ipc_CR >= CR_limit_IPC))
								state = 6;
							else if ((ipc_CR < CR_limit_IPC) && (ipc_NCR >= NCR_limit_IPC))
								state = 5;
							else
								state = 5;
							break;

						case 5:
						case 6:
							if (ipcTotal > UP_limit_IPC)
								idle = true;
							else if ((ipcTotal <= UP_limit_IPC) && (ipcTotal >= LOW_limit_IPC))
								state = 8;
							else if ((ipc_NCR < NCR_limit_IPC) && (ipc_CR >= CR_limit_IPC))
								state = 7;
							else if ((ipc_CR < CR_limit_IPC) && (ipc_NCR >= NCR_limit_IPC))
								state = 8;
							else // NCR and CR worse
								state = 8;
							break;

						case 7:
						case 8:
							if (ipcTotal > UP_limit_IPC)
								idle = true;
							else if ((ipcTotal <= UP_limit_IPC) && (ipcTotal >= LOW_limit_IPC))
								state = 5;
							else if ((ipc_NCR < NCR_limit_IPC) && (ipc_CR >= CR_limit_IPC))
								state = 6;
							else if ((ipc_CR < CR_limit_IPC) && (ipc_NCR >= NCR_limit_IPC))
								state = 5;
							else // NCR and CR worse
								state = 5;
							break;
					}

					// State actions switch-case
					switch (state)
					{
						case 1:
						case 2:
						case 3:
							if (idle)
								LOGINF("New IPC is better or equal-> {} idle intervals"_format(
										IDLE_INTERVALS));
							else
								LOGINF("No action performed");
							break;

						case 5:
							if (idle)
								LOGINF("New IPC is better or equal -> {} idle intervals"_format(
										IDLE_INTERVALS));
							else
							{
								LOGINF("NCR-- (Remove one shared way from CLOS with non-critical "
									   "apps)");
								newMaskNonCr = (maskNonCrCLOS >> 1) | 0x00010;
								maskNonCrCLOS = newMaskNonCr;
								LinuxBase::get_cat()->set_cbm(1, maskNonCrCLOS);
							}
							break;

						case 6:
							if (idle)
								LOGINF("New IPC is better or equal -> {} idle intervals"_format(
										IDLE_INTERVALS));
							else
							{
								LOGINF("CR-- (Remove one shared way from CLOS with critical apps)");
								newMaskCr = (maskCrCLOS << 1) & 0xfffff;
								maskCrCLOS = newMaskCr;
								LinuxBase::get_cat()->set_cbm(2, maskCrCLOS);
							}
							break;

						case 7:
							if (idle)
								LOGINF("New IPC is better or equal -> {} idle intervals"_format(
										IDLE_INTERVALS));
							else
							{
								LOGINF("NCR++ (Add one shared way to CLOS with non-critical apps)");
								newMaskNonCr = (maskNonCrCLOS << 1) | 0x00010;
								maskNonCrCLOS = newMaskNonCr;
								LinuxBase::get_cat()->set_cbm(1, maskNonCrCLOS);
							}
							break;

						case 8:
							if (idle)
								LOGINF("New IPC is better or equal -> {} idle intervals"_format(
										IDLE_INTERVALS));
							else
							{
								LOGINF("CR++ (Add one shared way to CLOS with critical apps)");
								newMaskCr = (maskCrCLOS >> 1) | 0x80000;
								maskCrCLOS = newMaskCr;
								LinuxBase::get_cat()->set_cbm(2, maskCrCLOS);
							}
							break;
						default:
							break;
					}

					num_ways_CLOS_1 = __builtin_popcount(LinuxBase::get_cat()->get_cbm(1));
					num_ways_CLOS_2 = __builtin_popcount(LinuxBase::get_cat()->get_cbm(2));

					LOGINF("COS 2 (CR)     has mask {:#x} ({} ways)"_format(
							LinuxBase::get_cat()->get_cbm(2), num_ways_CLOS_2));
					LOGINF("COS 1 (non-CR) has mask {:#x} ({} ways)"_format(
							LinuxBase::get_cat()->get_cbm(1), num_ways_CLOS_1));

					int64_t aux_ns = (num_ways_CLOS_2 + num_ways_CLOS_1) - 20;
					num_shared_ways = (aux_ns < 0) ? 0 : aux_ns;
					LOGINF("Number of shared ways: {}"_format(num_shared_ways));
					assert(num_shared_ways >= 0);

				} // if(critical>0 && critical<4)

			} // else if(!idle)
		}	 // else no es firstime
		LOGINF("Current state = {}"_format(state));
	} // if (current_interval >= firstInterval)

	// calculate new gradient

	ipc_CR_prev = ipc_CR;
	ipc_NCR_prev = ipc_NCR;

	// Assign total IPC of this interval to previos value
	expectedIPCtotal = ipcTotal;

} // apply


/////////////// CRITICAL PHASE-AWARE (CPA) ///////////////
/*
 * Update configuration method allows to change from one
 * cache configuration to another, i.e. when a different
 * number of critical apps is detected
 */
void CriticalPhaseAware::update_configuration(std::vector<pair_t> v, std::vector<pair_t> status,
										   uint64_t num_critical_old, uint64_t num_critical_new)
{

	uint64_t new_clos;

	// 1. Update global variables
	if ((num_critical_new == 0) || (num_critical_new > 4))
		state = 4;
	else
		state = num_critical_new;
	idle_count = idleIntervals;

	LOGINF("[UPDATE] From {} to {} critical apps"_format(num_critical_old, num_critical_new));

	// If 4 or 0 new critical apps are detected...
	// >> assign CLOSes mask 0xfffff
	// >> assign all apps to CLOS 1
	if ((num_critical_new == 0) || (num_critical_new >= 4)) {
		critical_apps = 0;
		LLC_ways_space = 0;
		for (int clos = 1; clos <= 6; clos += 1)
			LinuxBase::get_cat()->set_cbm(clos, mask_MAX);

		for (const auto &item : v) {
			uint32_t taskID = std::get<0>(item);
			uint64_t CLOS = std::get<1>(item);

			// Find PID corresponding to the ID
			auto it1 = std::find_if(id_pid.begin(), id_pid.end(), [&taskID](const auto &tuple) {
				return std::get<0>(tuple) == taskID;
			});
			pid_t taskPID = std::get<1>(*it1);

			auto it2 = std::find_if(
					taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
					[&taskID](const auto &tuple) { return std::get<0>(tuple) == taskID; });

			if ((CLOS >= 2) && (CLOS <= 4)) {
				LinuxBase::get_cat()->add_task(1, taskPID);
				CLOS_critical.insert(CLOS);
				it2 = taskIsInCRCLOS.erase(it2);
				taskIsInCRCLOS.push_back(std::make_pair(taskID, 1));
				limit_task[taskID] = false;
				limit = false;
			} else if ((CLOS >= 5) && (CLOS <= 6)) {
				// Return only to CLOS 1 Non-critical greedy applications
				if (excluded[taskID] == false) {
					LOGINF("[UPDATE] Include non-critical greedy task {} in CLOS 1"_format(taskID));
					include_application(taskID, taskPID, it2, CLOS);
					limit_task[taskID] = false;
				} else
					LOGINF("[UPDATE] Remain squaderer task {} in CLOS {}"_format(taskID, CLOS));
			}
		}

		LOGINF("[UPDATE] All critical tasks are assigned to CLOS 1. TaskIsInCRCLOS updated");
		return;
	}

	CLOS_critical = {2, 3, 4};

	// If 1, 2 or 3 critical apps are detected
	for (const auto &item : v) {
		uint32_t taskID = std::get<0>(item);
		// Find status
		auto it = std::find_if(status.begin(), status.end(), [&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		// Find PID
		auto it1 = std::find_if(id_pid.begin(), id_pid.end(), [&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		pid_t taskPID = std::get<1>(*it1);

		// Add applications to CLOS 1 or 2
		// depending on their new status
		if (it != status.end()) {
			uint64_t cr_val = std::get<1>(*it);
			auto it2 = std::find_if(
					taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
					[&taskID](const auto &tuple) { return std::get<0>(tuple) == taskID; });
			if (cr_val) {
				// cr_val will be 1 for the new critical apps
				if (!CLOS_critical.empty()) {
					auto itC = CLOS_critical.begin();
					new_clos = *itC;
					LinuxBase::get_cat()->add_task(new_clos, taskPID);
					itC = CLOS_critical.erase(itC);
					limit_task[taskID] = false;
				} else {
					LOGERR("Empty CLOS_critical");
					assert(0 > 1);
				}
			} else {
				// cr_val will be 0 for the new non-critical apps
				LinuxBase::get_cat()->add_task(1, taskPID);
				new_clos = 1;
				uint32_t clos = std::get<1>(*it2);
				CLOS_critical.insert(clos);
				limit_task[taskID] = false;
			}

			// update taskIsInCRCLOS
			it2 = taskIsInCRCLOS.erase(it2);
			taskIsInCRCLOS.push_back(std::make_pair(taskID, new_clos));
		}
	}

	// 3. Assign preconfigured masks to CLOSes 1, 2, 3 and 4
	uint64_t maskCR = mask_MAX;
	uint64_t maskNCR = mask_MAX;
	switch (num_critical_new) {
		case 1:
			maskNCR = mask_NCRCLOS_1;
			maskCR = mask_CRCLOS_1;
			break;
		case 2:
			maskNCR = mask_NCRCLOS_2;
			maskCR = mask_CRCLOS_2;
			break;
		case 3:
			maskNCR = mask_NCRCLOS_3;
			maskCR = mask_CRCLOS_3;
		default:
			break;
	}

	LinuxBase::get_cat()->set_cbm(1, maskNCR);
	LinuxBase::get_cat()->set_cbm(2, maskCR);
	LinuxBase::get_cat()->set_cbm(3, maskCR);
	LinuxBase::get_cat()->set_cbm(4, maskCR);
	uint64_t ways = __builtin_popcount(maskNCR);
	LOGINF("[UPDATE] CLOS 1 (non-CR) has mask {:#x} ({} ways)"_format(LinuxBase::get_cat()->get_cbm(1), ways));
	ways = __builtin_popcount(maskCR);
	LLC_ways_space = ways;
	LOGINF("[UPDATE] CLOSes 2,3,4 (CR) have masks {:#x} ({} ways)"_format(LinuxBase::get_cat()->get_cbm(2), ways));

	idle = true;
	limit = false;
}

void CriticalPhaseAware::isolate_application(uint32_t taskID, pid_t taskPID,
										  std::vector<pair_t>::iterator it)
{
	uint64_t CLOS_isolated;
	// Isolate it in a separate CLOS with two shared ways
	n_isolated_apps++;
	LOGINF("[ISO] n_isolated_apps = {}"_format(n_isolated_apps));
	auto closIT = isolated_closes.begin();
	CLOS_isolated = *closIT;
	closIT = isolated_closes.erase(closIT);
	id_isolated.push_back(taskID);

	LinuxBase::get_cat()->add_task(CLOS_isolated, taskPID);
	LOGINF("[ISO] {}: assigned to CLOS {}"_format(taskID, CLOS_isolated));

	if (n_isolated_apps == 2) {
		LinuxBase::get_cat()->set_cbm(5, mask_iso_2);
		LinuxBase::get_cat()->set_cbm(6, mask_iso_2);
		uint64_t ways = __builtin_popcount(mask_iso_2);
		LOGINF("[ISO] CLOSes 5 and 6  have mask {:#x} ({} ways)"_format(mask_iso_2, ways));
	} else {
		LinuxBase::get_cat()->set_cbm(CLOS_isolated, mask_iso_1);
		uint64_t ways = __builtin_popcount(mask_iso_1);
		LOGINF("[ISO] CLOS {} has mask {:#x} ({} ways)"_format(CLOS_isolated, mask_iso_1, ways));
	}

	// Update taskIsInCRCLOS
	it = taskIsInCRCLOS.erase(it);
	taskIsInCRCLOS.push_back(std::make_pair(taskID, CLOS_isolated));
}

void CriticalPhaseAware::include_application(uint32_t taskID, pid_t taskPID,
										  std::vector<pair_t>::iterator it, uint64_t CLOSvalue)
{
	isolated_closes.insert(isolated_closes.begin(), CLOSvalue);
	LOGINF("[ISO] CLOS {} pushed back to isolated_closes"_format(CLOSvalue));
	n_isolated_apps--;
	if (n_isolated_apps == 1) {
		if (CLOSvalue == 5)
			LinuxBase::get_cat()->set_cbm(6, mask_iso_1);
		else
			LinuxBase::get_cat()->set_cbm(5, mask_iso_1);
	}
	LOGINF("[ISO] n_isolated_apps = {}"_format(n_isolated_apps));
	id_isolated.erase(std::remove(id_isolated.begin(), id_isolated.end(), taskID),
					  id_isolated.end());

	LinuxBase::get_cat()->add_task(1, taskPID);
	it = taskIsInCRCLOS.erase(it);
	taskIsInCRCLOS.push_back(std::make_pair(taskID, 1));
	excluded[taskID] = false;
	LOGINF("[ISO] {}: return to CLOS 1"_format(taskID));
}

void CriticalPhaseAware::divide_3_critical(uint64_t clos, bool limitDone)
{
	uint64_t schem = LinuxBase::get_cat()->get_cbm(clos);
	uint32_t ways = __builtin_popcount(LinuxBase::get_cat()->get_cbm(clos));
	uint32_t half_ways = 0;
	LOGINF("[LLC] Limit {}!"_format(limitDone));

	if (!limitDone) {
		// Reduce one third the number of ways of clos
		if (ways <= 2)
			LOGINF("[LLC] Already reached minimum ways!");
		else
			half_ways = ways/3;
	} else {
		// Reduce two thirds the number of ways of clos
		if (ways <= 2)
			LOGINF("[LLC] Already reached minimum ways!");
		else
			half_ways = 2 * (ways/3);
	}

	LOGINF("[LLC] CLOS {} reduced from {} to {} ways"_format(clos,ways,half_ways));
	uint32_t reduced_ways = ways - half_ways;
	for(uint32_t i=0; i<reduced_ways; i++)
		schem = (schem << 1) & mask_MAX;
	LOGINF("[LLC] CLOS {} new mask: {:#x}"_format(clos, schem));
	LinuxBase::get_cat()->set_cbm(clos,schem);
}

void CriticalPhaseAware::divide_half_ways_critical(uint64_t clos, uint32_t cr_apps)
{
	// 1. Reduce half the number of ways of clos
	uint64_t schem = LinuxBase::get_cat()->get_cbm(clos);
	uint32_t ways = __builtin_popcount(LinuxBase::get_cat()->get_cbm(clos));
	if (ways <= 2) {
		LOGINF("[LLC] Already reached minimum ways!");
	} else {
		uint32_t half_ways = ways/2;
		LOGINF("[LLC] CLOS {} reduced from {} to {} ways"_format(clos,ways,half_ways));
		uint32_t reduced_ways = ways - half_ways;
		for(uint32_t i=0; i<reduced_ways; i++)
			schem = (schem << 1) & mask_MAX;
		LOGINF("[LLC] CLOS {} new mask: {:#x}"_format(clos, schem));
		LinuxBase::get_cat()->set_cbm(clos,schem);
	}

	// 2. Increase CLOS 1 space
	if (cr_apps == 1) {
		ways = __builtin_popcount(LinuxBase::get_cat()->get_cbm(1));
		uint32_t ways_critical = __builtin_popcount(schem);
		LLC_ways_space = ways_critical;
		uint32_t diff = ((ways_MAX + 2) - ways_critical) - ways;
		schem = LinuxBase::get_cat()->get_cbm(1);
		for(uint32_t i=0; i<diff; i++)
			schem = (schem << 1) | mask_min_right;
		LOGINF("[LLC] CLOS 1 new mask: {:#x}"_format(schem));
		LinuxBase::get_cat()->set_cbm(1,schem);
	}
}

// Comparison function to sort the vector elements
// by second element of tuples
bool sortbysec(const std::tuple<uint32_t, double>& a,
		   const std::tuple<uint32_t, double>& b)
{
	return (std::get<1>(a) > std::get<1>(b));
}


void CriticalPhaseAware::apply(uint64_t current_interval, const tasklist_t &tasklist) {
	LOGINF("CAT Policy name: Critical Phase-Aware");
	LOGINF("Current_interval = {}"_format(current_interval));

	// Apply only when the amount of intervals specified has passed
	if (current_interval % every != 0)
		return;

	// (Core, MPKI-L3) tuple
	auto v_mpkil3 = std::vector<pairD_t>();
	auto v_hpkil3 = std::vector<pairD_t>();
	auto v_ipc = std::vector<pairD_t>();
	auto v_l3_occup_mb = std::vector<pairD_t>();
	auto id_phase_change = std::vector<uint32_t>();

	// Set holding all MPKI-L3 values from a given interval
	// used to compute the value of limit_outlier
	auto all_mpkil3 = std::set<double>();

	// Apps that have changed to  critical (1) or to non-critical (0)
	auto status = std::vector<pair_t>();

	// Vector with outlier values (1 == outlier, 0 == not outlier)
	auto outlier = std::vector<pair_t>();

	double ipcTotal = 0, mpkiL3Total = 0;
	double ipc_CR = 0;
	double ipc_NCR = 0;
	double l3_occup_mb_total = 0;
	double ipc_ICOV = 0;

	uint32_t taskID;
	pid_t taskPID;

	// Accumulator to calculate mean and std of mpkil3
	ca_accum_t macc;

	// Number of critical apps found in the interval
	bool change_in_outliers = false;

	// Gather data
	LOGINF("—————– STEPS 1 & 2 —————–");
	for (const auto &task_ptr : tasklist) {
		const Task &task = *task_ptr;
		std::string taskName = task.name;
		taskPID = task.pid;
		taskID = task.id;
		double my_sum, prev_sum;

		// stats per interval
		uint64_t l3_miss = task.stats.last("mem_load_uops_retired.l3_miss");
		uint64_t l3_hit = task.stats.last("mem_load_uops_retired.l3_hit");
		uint64_t inst = task.stats.last("instructions");
		double ipc = task.stats.last("ipc");
		double l3_occup_mb = task.stats.last("intel_cqm/llc_occupancy/") / 1024 / 1024;
		l3_occup_mb_total += l3_occup_mb;
		double MPKIL3 = (double)(l3_miss * 1000) / (double)inst;
		double HPKIL3 = (double)(l3_hit * 1000) / (double)inst;

		LOGINF("Task {} ({}): IPC = {}, HPKIL3 = {}, MPKIL3 = {}, l3_occup_mb {}"_format(
				taskName, taskID, ipc, HPKIL3, MPKIL3, l3_occup_mb));

		// Create tuples and add them to vectors
		v_mpkil3.push_back(std::make_pair(taskID, MPKIL3));
		v_hpkil3.push_back(std::make_pair(taskID, HPKIL3));
		v_l3_occup_mb.push_back(std::make_pair(taskID, l3_occup_mb));
		v_ipc.push_back(std::make_pair(taskID, ipc));
		id_pid.push_back(std::make_pair(taskID, taskPID));

		// Accumulate total values
		ipcTotal += ipc;
		mpkiL3Total += MPKIL3;

		// Update queue of each task with last value of MPKI-L3
		auto it2 = valid_mpkil3.find(taskID);
		if (it2 != valid_mpkil3.end()) {
			std::deque<double> deque_mpkil3 = it2->second;

			// Remove values until vector size is equal to sliding window size
			while (deque_mpkil3.size() >= windowSize)
				deque_mpkil3.pop_back();

			auto itT = std::find_if(
					taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
					[&taskID](const auto &tuple) { return std::get<0>(tuple) == taskID; });
			uint64_t CLOSvalue = std::get<1>(*itT);

			ipc_sumXij[taskID] += ipc;
			ipc_phase_duration[taskID] += 1;
			if ((CLOSvalue == 5) | (CLOSvalue == 6))
				LOGINF("[ISO] Isolated task {} ({}) is in CLOS {} and has IPC {}"_format(
						taskID, taskName, CLOSvalue, ipc));

			// Calculate IPC ICOV for each task
			my_sum = ipc_sumXij[taskID] / ipc_phase_duration[taskID];
			prev_sum = (ipc_sumXij[taskID] - ipc) / (ipc_phase_duration[taskID] - 1);
			ipc_ICOV = fabs(ipc - prev_sum) / my_sum;
			LOGINF("{}: ipc_icov = {} ({})"_format(taskID, ipc_ICOV, ipc));
			// Application phase-change checking
			if (ipc_ICOV >= icov) {
				uint32_t count = task_increase_ipc_count(*task_ptr);
				LOGINF("{}: IPC PHASE CHANGE {}"_format(taskID, count));
				ipc_phase_duration[taskID] = 1;
				ipc_sumXij[taskID] = ipc;
				id_phase_change.push_back(taskID);

				// Check if medium app is no longer medium
				if ((limit_task[taskID]) && (ipc < ipcMedium) && (CLOSvalue >= 2) &&
					(CLOSvalue <= 4)) {
					LOGINF("[LLC] Limiting task {} was not good! -> return its ways"_format(taskID));
					limit_task[taskID] = false;
					limit = false;
					uint64_t ways = 20;
					if (critical_apps == 1) {
						LinuxBase::get_cat()->set_cbm(1, mask_NCRCLOS_1);
						ways = __builtin_popcount(mask_NCRCLOS_1);
						LOGINF("[LLC] CLOS 1 now has mask {:#x} ({} ways)"_format(mask_NCRCLOS_1, ways));
						LinuxBase::get_cat()->set_cbm(CLOSvalue, mask_CRCLOS_1);
						ways = __builtin_popcount(mask_CRCLOS_1);
						LLC_ways_space = ways;
						LOGINF("[LLC] CLOS {} now has mask {:#x} ({} ways)"_format(CLOSvalue, mask_CRCLOS_1, ways));
					} else if (critical_apps == 2) {
						LinuxBase::get_cat()->set_cbm(CLOSvalue, mask_CRCLOS_2);
						ways = __builtin_popcount(mask_CRCLOS_2);
						LOGINF("[LLC] CLOS {} now has mask {:#x} ({} ways)"_format(CLOSvalue, mask_CRCLOS_2, ways));
					} else if (critical_apps == 3) {
						LinuxBase::get_cat()->set_cbm(CLOSvalue, mask_CRCLOS_3);
						ways = __builtin_popcount(mask_CRCLOS_3);
						LOGINF("[LLC] CLOS {} now has mask {:#x} ({} ways)"_format(CLOSvalue, mask_CRCLOS_3, ways));
					}
				}
				// Check if non-critical app is no longer gready
				if (((CLOSvalue == 5) || (CLOSvalue == 6)) && (limit_task[taskID]) && ((HPKIL3 >= 0.5) || (MPKIL3 >= 0.5))) {
					LOGINF("[ISO] Task {} is now non-critical!"_format(taskID));
					include_application(taskID,taskPID,itT,CLOSvalue);
					limit_task[taskID]= false;
					//countCLOS = task_increase_clos_change_count(*taskCLOS);
				}

			} else if (current_interval == firstInterval)
				id_phase_change.push_back(taskID);

			// Add to valid_mpkil3 queue
			if (excluded[taskID] == false)
				deque_mpkil3.push_front(MPKIL3);

			// Store queue modified in the dictionary
			valid_mpkil3[taskID] = deque_mpkil3;
		} else {
			// Add a new entry in the dictionary
			LOGINF("NEW ENTRY IN DICT valid_mpkil3 added");
			valid_mpkil3[taskID].push_front(MPKIL3);
			taskIsInCRCLOS.push_back(std::make_pair(taskID, 1));
			ipc_phase_duration[taskID] = 1;
			ipc_sumXij[taskID] = ipc;
			excluded[taskID] = false;
		}
	}
	LOGINF("Total L3 occupation: {}"_format(l3_occup_mb_total));
	LOGINF("IPC total: {}"_format(ipcTotal));

	if (current_interval < firstInterval) {
		id_pid.clear();
		id_phase_change.clear();
		return;
	}

	// Add values of MPKI-L3 from each app to the common set
	LOGINF("-MPKIL3-");
	for (auto const &x : valid_mpkil3) {
		// Get deque
		std::deque<double> val = x.second;
		taskID = x.first;
		std::string res;

		// Add values
		if (excluded[taskID] == false) {
			for (auto i = val.cbegin(); i != val.cend(); ++i) {
				res = res + std::to_string(*i) + " ";
				macc(*i);
				all_mpkil3.insert(*i);
			}
			LOGINF(res);
		} else
			LOGINF("Task {} is excluded!!!"_format(taskID));
	}
	// Calculate limit outlier for MPKI-L3
	double mean = acc::mean(macc);
	double var = acc::variance(macc);
	double limit_outlier = mean + 1.5 * std::sqrt(var);
	LOGINF("MPKIL3 1.5std: {} -> mean {}, var {}"_format(limit_outlier, mean, var));
	if (limit_outlier < 1)
		limit_outlier = 1;
	LOGINF("Threshold MPKIL3_H = {}"_format(limit_outlier));
	LOGINF("Threshold HPKIL3_notVL = {}"_format(hpkil3Limit));

	for (auto const &x : id_phase_change) {
		taskID = x;

		// Find HPKIL3
		auto itH = std::find_if(v_hpkil3.begin(), v_hpkil3.end(), [&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		double HPKIL3Task = std::get<1>(*itH);

		// Find MPKIL3
		auto itM = std::find_if(v_mpkil3.begin(), v_mpkil3.end(), [&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		double MPKIL3Task = std::get<1>(*itM);

		// Find IPC
		auto itI = std::find_if(v_ipc.begin(), v_ipc.end(), [&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		double IPCTask = std::get<1>(*itI);

		// Find CLOS
		auto itT =
				std::find_if(taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
							 [&taskID](const auto &tuple) { return std::get<0>(tuple) == taskID; });
		uint64_t CLOSvalue = std::get<1>(*itT);

		// Find PID
		auto it1 = std::find_if(id_pid.begin(), id_pid.end(), [&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		taskPID = std::get<1>(*it1);


		//uint32_t countCLOS;
		//const auto &taskCLOS = tasks_find(tasklist, taskID);
		switch (CLOSvalue) {
			case 1:  // Non-critical
				if ((MPKIL3Task >= 10) && (HPKIL3Task >= 10) && (IPCTask <= ipcLow)){
					// 1. BULLY
					excluded[taskID] = true;
					outlier.push_back(std::make_pair(taskID, 0));
					LOGINF("Task {} is a BULLY --> exclude and remain in CLOS 1"_format(taskID));
					//countCLOS = task_increase_clos_change_count(*taskCLOS);
				} else if ((MPKIL3Task >= limit_outlier) && (HPKIL3Task < hpkil3Limit)) {
					// 2. SQUANDERER
					LOGINF("The MPKI_L3 of task {} is an outlier but HPKIL3 is very low {}!! -> SQUANDERER"_format(
							taskID, HPKIL3Task));
					if (n_isolated_apps < 2)
						isolate_application(taskID, taskPID, itT);
					else
						LOGINF("There are no isolated CLOSes available --> remain in CLOS 1");
					outlier.push_back(std::make_pair(taskID, 0));
					excluded[taskID] = true;
					//countCLOS = task_increase_clos_change_count(*taskCLOS);
				} else {
					if ((MPKIL3Task >= limit_outlier) && (HPKIL3Task >= hpkil3Limit) && (IPCTask <= ipcMedium)) {
						// 3. CRITICAL
						LOGINF("The MPKI_L3 of task {} is an outlier, since MPKIL3 {} >= {} && HPKIL3 {} >= {}"_format(
								taskID, MPKIL3Task, limit_outlier, HPKIL3Task, hpkil3Limit));
						outlier.push_back(std::make_pair(taskID, 1));
						critical_apps++;
						change_in_outliers = true;
						//countCLOS = task_increase_clos_change_count(*taskCLOS);
					} else {
						// 5. NON-CRITICAL
						LOGINF("Task {} is still non-critical!"_format(taskID));
						outlier.push_back(std::make_pair(taskID, 0));
					}

					// Non-exclude task if it is no longer squanderer or bully
					if (excluded[taskID] == true) {
						excluded[taskID] = false;
						valid_mpkil3[taskID].clear();
						valid_mpkil3[taskID].push_front(MPKIL3Task);
					}
				}
				break;

			case 2:
			case 3:
			case 4: // Critical
				if ((HPKIL3Task > MPKIL3Task) && (MPKIL3Task < limit_outlier)) {
					// 1. PROFITABLE CRITICAL
					LOGINF("Critical task {} is profitable so continue critical"_format(taskID));
					outlier.push_back(std::make_pair(taskID, 1));
				} else if ((MPKIL3Task >= 10) && (HPKIL3Task >= 10) && (IPCTask <= ipcLow)) {
					// 2. BULLY
					excluded[taskID] = true;
					change_in_outliers = true;
					outlier.push_back(std::make_pair(taskID, 0));
					LOGINF("Task {} is a bully--> exclude and CLOS 1"_format(taskID));
					// LLCoccup_critical.erase(taskID);
					CLOS_critical.insert(CLOSvalue);
					critical_apps--;
					//countCLOS = task_increase_clos_change_count(*taskCLOS);
				} else if ((MPKIL3Task >= limit_outlier) && (HPKIL3Task >= hpkil3Limit)) {
					// 3. STILL CRITICAL
					LOGINF("Task {} is still critical!"_format(taskID));
					outlier.push_back(std::make_pair(taskID, 1));
				} else if ((MPKIL3Task >= limit_outlier) && (HPKIL3Task < hpkil3Limit)) {
					// 4. SQUANDERER
					LOGINF("The MPKI_L3 of task {} is an outlier but HPKIL3 is very low {}!! -> SQUANDERER"_format(
							taskID, HPKIL3Task));
					if (n_isolated_apps < 2)
						isolate_application(taskID, taskPID, itT);
					else
						LOGINF("There are no isolated CLOSes available --> remain in CLOS 1");
					outlier.push_back(std::make_pair(taskID, 0));
					excluded[taskID] = true;
					critical_apps--;
					//countCLOS = task_increase_clos_change_count(*taskCLOS);
				} else {
					// 5. NON-CRITICAL
					LOGINF("Task {} is now non-critical!"_format(taskID));
					outlier.push_back(std::make_pair(taskID, 0));
					change_in_outliers = true;
					CLOS_critical.insert(CLOSvalue);
					critical_apps--;
					//countCLOS = task_increase_clos_change_count(*taskCLOS);
				}
				break;

			case 5:
			case 6: // Non-critical greedy or squanderer
				if ((MPKIL3Task >= 10) && (HPKIL3Task >= 10) && (IPCTask <= ipcLow)) {
					// 1. BULLY
					excluded[taskID] = true;
					include_application(taskID, taskPID, itT, CLOSvalue);
					outlier.push_back(std::make_pair(taskID, 0));
					LOGINF("Task {} is a bully--> exclude and CLOS 1"_format(taskID));
					//countCLOS = task_increase_clos_change_count(*taskCLOS);
				} else if ((MPKIL3Task >= limit_outlier) && (HPKIL3Task < hpkil3Limit)) {
					// 2. SQUANDERER
					LOGINF("[ISO] Task {} is still a SQUANDERER!"_format(taskID));
					outlier.push_back(std::make_pair(taskID, 0));
					excluded[taskID] = true;
				} else {
					if ((MPKIL3Task >= limit_outlier) && (HPKIL3Task >= hpkil3Limit) && (IPCTask <= ipcMedium)) {
						// 3. CRITICAL
						LOGINF("The MPKI_L3 of task {} is an outlier, since MPKIL3 {} >= {} && HPKIL3 {} >= {}"_format(
								taskID, MPKIL3Task, limit_outlier, HPKIL3Task, hpkil3Limit));
						include_application(taskID, taskPID, itT, CLOSvalue);
						outlier.push_back(std::make_pair(taskID, 1));
						critical_apps++;
						change_in_outliers = true;
						//countCLOS = task_increase_clos_change_count(*taskCLOS);
					} else if (limit_task[taskID]) {
						LOGINF("[ISO] Task is non-critical greedy!");
					} else {
						// 5. NON-CRITICAL
						LOGINF("Task {} is now non-critical!"_format(taskID));
						include_application(taskID, taskPID, itT, CLOSvalue);
						outlier.push_back(std::make_pair(taskID, 0));
						//countCLOS = task_increase_clos_change_count(*taskCLOS);
					}
					// Non-exclude task if it is no longer squanderer or bully
					if (excluded[taskID] == true) {
						excluded[taskID] = false;
						valid_mpkil3[taskID].clear();
						valid_mpkil3[taskID].push_front(MPKIL3Task);
					}
				}
				break;
		}
	}

	LOGINF("critical_apps = {}"_format(critical_apps));

	for (auto const &x : taskIsInCRCLOS) {
		taskID = std::get<0>(x);
		uint64_t CLOSvalue = std::get<1>(x);
		auto it1 = std::find_if(outlier.begin(), outlier.end(), [&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		// Find L3 Occupancy (MB)
		auto itL3 =
				std::find_if(v_l3_occup_mb.begin(), v_l3_occup_mb.end(),
							 [&taskID](const auto &tuple) { return std::get<0>(tuple) == taskID; });
		double l3_occup_mb = std::get<1>(*itL3);

		switch (CLOSvalue) {
			case 2:
			case 3:
			case 4:
				if (it1 == outlier.end())
					outlier.push_back(std::make_pair(taskID, 1));
				LOGINF("[LLC] Task {} CLOS {} addded to LLCoccup_critical"_format(taskID, CLOSvalue));
				LLCoccup_critical[taskID] = l3_occup_mb;
				break;
			case 1:
				LLCoccup_noncritical.push_back(std::make_pair(taskID, l3_occup_mb));
			case 5:
			case 6:
				if (it1 == outlier.end())
					outlier.push_back(std::make_pair(taskID, 0));
				break;
		}
	}

	for (const auto &myPair : LLCoccup_critical) {
		LLC_critical+= myPair.second;
	}
	LOGINF("[LLC] Total LLCoccup_critical = {}"_format(LLC_critical));

	// Check CLOS are configured to the correct mask
	uint64_t ways = 20;
	if (firstTime) {
		// Set ways of CLOSes 1 and 2, [3, 4]
		switch (critical_apps) {
			case 1:
				// 1 critical app
				// 60% ways critical
				// 50% ways non-critical
				LinuxBase::get_cat()->set_cbm(1, mask_NCRCLOS_1);
				LinuxBase::get_cat()->set_cbm(2, mask_CRCLOS_1);
				ways = __builtin_popcount(mask_NCRCLOS_1);
				LOGINF("CLOS 1 (non-CR) now has mask {:#x} ({} ways)"_format(mask_NCRCLOS_1, ways));
				ways = __builtin_popcount(mask_CRCLOS_1);
				LLC_ways_space = ways;
				LOGINF("CLOS 2 (CR) now has mask {:#x} ({} ways)"_format(mask_CRCLOS_1, ways));
				state = 1;
				break;
			case 2:
				// 2 critical apps
				// 65% ways critical
				// 45% ways non-critical
				LinuxBase::get_cat()->set_cbm(1, mask_NCRCLOS_2);
				LinuxBase::get_cat()->set_cbm(2, mask_CRCLOS_2);
				LinuxBase::get_cat()->set_cbm(3, mask_CRCLOS_2);
			 	ways = __builtin_popcount(mask_NCRCLOS_2);
				LOGINF("CLOS 1 (non-CR) now has mask {:#x} ({} ways)"_format(mask_NCRCLOS_2, ways));
				ways = __builtin_popcount(mask_CRCLOS_2);
				LLC_ways_space = ways;
				LOGINF("CLOSes 2 3 (CR) now have mask {:#x} ({} ways)"_format(mask_CRCLOS_2, ways));
				state = 2;
				break;
			case 3:
				// 3 critical apps
				// 70% ways critical
				// 40% ways non-critical
				LinuxBase::get_cat()->set_cbm(1, mask_NCRCLOS_3);
				LinuxBase::get_cat()->set_cbm(2, mask_CRCLOS_3);
				LinuxBase::get_cat()->set_cbm(3, mask_CRCLOS_3);
				LinuxBase::get_cat()->set_cbm(4, mask_CRCLOS_3);
				ways = __builtin_popcount(mask_NCRCLOS_3);
				LOGINF("CLOS 1 (non-CR) now has mask {:#x} ({} ways)"_format(mask_NCRCLOS_3, ways));
				ways = __builtin_popcount(mask_CRCLOS_3);
				LLC_ways_space = ways;
				LOGINF("CLOSes 2 3 4 (CR) now have mask {:#x} ({} ways)"_format(mask_CRCLOS_3, ways));
				state = 3;
				break;
			default:
				// More than 3 or no critical apps
				// 100% ways critical
				// 100% ways non-critical
				state = 4;
				break;
		}

		if (state != 4) {
			firstTime = 0;
			idle = true;

			// Assign each core to its corresponding CLOS
			for (const auto &item : outlier) {
				taskID = std::get<0>(item);
				uint32_t outlierValue = std::get<1>(item);
				// Find PID
				auto it1 = std::find_if(id_pid.begin(), id_pid.end(), [&taskID](const auto &tuple) {
					return std::get<0>(tuple) == taskID;
				});
				taskPID = std::get<1>(*it1);
				// Find IPC
				auto it = std::find_if(v_ipc.begin(), v_ipc.end(), [&taskID](const auto &tuple) {
					return std::get<0>(tuple) == taskID;
				});
				double ipcTask = std::get<1>(*it);
				// Find CLOS value
				auto itT = std::find_if(
						taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
						[&taskID](const auto &tuple) { return std::get<0>(tuple) == taskID; });
				uint64_t CLOSvalue = std::get<1>(*itT);

				auto itC = CLOS_critical.begin();

				if (outlierValue) {
					limit_task[taskID] = false;
					LinuxBase::get_cat()->add_task(*itC, taskPID);
					LOGINF("Task ID {} assigned to CLOS {}"_format(taskID, *itC));
					itT = taskIsInCRCLOS.erase(itT);
					taskIsInCRCLOS.push_back(std::make_pair(taskID, *itC));
					itC = CLOS_critical.erase(itC);
					ipc_CR += ipcTask;
				} else if (CLOSvalue < 5) {
					LinuxBase::get_cat()->add_task(1, taskPID);
					LOGINF("Task ID {} assigned to CLOS 1"_format(taskID));
					itT = taskIsInCRCLOS.erase(itT);
					taskIsInCRCLOS.push_back(std::make_pair(taskID, 1));
					ipc_NCR += ipcTask;
				} else if (CLOSvalue >= 5) {
					LOGINF("[ISO] Task ID {} isolated in CLOS {}"_format(taskID, CLOSvalue));
					ipc_NCR += ipcTask;
				}
			}
		}
	} else {
		// Check if there is a new critical app
		for (const auto &item : outlier) {
			taskID = std::get<0>(item);
			uint32_t outlierValue = std::get<1>(item);
			// Find IPC
			auto it = std::find_if(v_ipc.begin(), v_ipc.end(), [&taskID](const auto &tuple) {
				return std::get<0>(tuple) == taskID;
			});
			double ipcTask = std::get<1>(*it);
			// Find CLOS
			auto it2a = std::find_if(
					taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
					[&taskID](const auto &tuple) { return std::get<0>(tuple) == taskID; });
			uint64_t CLOSvalue = std::get<1>(*it2a);
			LOGINF("{}: CLOS {}"_format(taskID, CLOSvalue));
			assert((CLOSvalue >= 1) & (CLOSvalue <= 10));

			if (outlierValue && ((CLOSvalue == 1) || (CLOSvalue >= 5))) {
				LOGINF("There is a new critical app (outlier {}, current CLOS {})"_format(
						outlierValue, CLOSvalue));
				status.push_back(std::make_pair(taskID, 1));
				change_in_outliers = true;
				ipc_CR += ipcTask;
			} else if (!outlierValue && (CLOSvalue >= 2) && (CLOSvalue <= 4)) {
				LOGINF("There is a critical app that is no longer critical)");
				status.push_back(std::make_pair(taskID, 0));
				change_in_outliers = true;
				ipc_NCR += ipcTask;
			} else if (outlierValue) {
				ipc_CR += ipcTask;
				status.push_back(std::make_pair(taskID, 1));
			} else
				ipc_NCR += ipcTask;
		}

		// Update configuration if there is a change in critical apps
		if (change_in_outliers) {
			LOGINF("UPDATE CONFIGURATION");
			update_configuration(taskIsInCRCLOS, status, prev_critical_apps, critical_apps);
			LOGINF("Current state = {}"_format(state));
			LOGINF("IPC Total = {}"_format(ipcTotal));
			ipc_CR_prev = ipc_CR;
			ipc_NCR_prev = ipc_NCR;
			expectedIPCtotal = ipcTotal;
			prev_critical_apps = critical_apps;
			id_pid.clear();
			id_phase_change.clear();
			LLCoccup_critical.clear();
			LLCoccup_noncritical.clear();
			LLC_critical = 0;
			return;
		}
	}
	bool change_critical = false;
	LOGINF("—————– STEP 3 —————–");
	if ((critical_apps > 0) && (critical_apps < 4)) {
		for (const auto &myPair : LLCoccup_critical) {
			double occup = myPair.second;
			taskID = myPair.first;
			LOGINF("[LLC] {}: occup {} / {}"_format(myPair.first, occup, LLC_ways_space));

			if ((limit_task[taskID] == false) && (occup >= (LLC_ways_space/2))) {
				// Find CLOS
				auto it2 = std::find_if(taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
										[&taskID](const auto &tuple) {
											return std::get<0>(tuple) == taskID;
										});
				uint64_t CLOSvalue = std::get<1>(*it2);
				//const auto &taskCLOS = tasks_find(tasklist, taskID);
				// Find IPC
				auto it = std::find_if(v_ipc.begin(), v_ipc.end(),
									   [&taskID](const auto &tuple) {
										   return std::get<0>(tuple) == taskID;
									   });
				double ipcTask = std::get<1>(*it);
				if (ipcTask >= ipcMedium) {
					LOGINF("[LLC] Medium behavior! Limit space to CLOS {}"_format(CLOSvalue));
					if ((critical_apps < 3) && (limit == false))
						divide_half_ways_critical(CLOSvalue, critical_apps);
					else if (critical_apps == 3)
						divide_3_critical(CLOSvalue, limit);

					limit_task[taskID] = true;
					limit = true;
					change_critical = true;
					//uint32_t countCLOS = task_increase_clos_change_count(*taskCLOS);
					break;
				} else {
					LOGINF("[LLC] {}: IPCtask ({}) does not fullfil criteria to limit!"_format(taskID, ipcTask));
				}
			}
		}
	} else {
		LOGINF("[LLC] No critical apps! Jump step...");
	}

	LOGINF("—————– STEP 4 —————–");
	// Order vector in descending order of LLC occupancy
	std::sort(LLCoccup_noncritical.begin(), LLCoccup_noncritical.end(), sortbysec);

	// Calculate limit space to consider a task Greedy
	double limit_space = __builtin_popcount(LinuxBase::get_cat()->get_cbm(1)) / 3;
	if (limit_space < limit_space_ncr)
		limit_space = limit_space_ncr;

	for (const auto &item : LLCoccup_noncritical) {
		taskID = std::get<0>(item);
		double l3_occup_mb = std::get<1>(item);

		// Find PID
		auto it1 = std::find_if(id_pid.begin(), id_pid.end(), [&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		taskPID = std::get<1>(*it1);

		// Find CLOS
		auto itT = std::find_if(taskIsInCRCLOS.begin(), taskIsInCRCLOS.end(),
							[&taskID](const auto &tuple) { return std::get<0>(tuple) == taskID; });

		// Find HPKIL3
		auto itH = std::find_if(v_hpkil3.begin(), v_hpkil3.end(), [&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		double HPKIL3Task = std::get<1>(*itH);

		// Find MPKIL3
		auto itM = std::find_if(v_mpkil3.begin(), v_mpkil3.end(), [&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		double MPKIL3Task = std::get<1>(*itM);

		// Find IPC
		auto it = std::find_if(v_ipc.begin(), v_ipc.end(),[&taskID](const auto &tuple) {
			return std::get<0>(tuple) == taskID;
		});
		double ipcTask = std::get<1>(*it);

		if ((ipcTask >= ipcMedium) && (l3_occup_mb >= limit_space) && (HPKIL3Task < 0.5) && (MPKIL3Task < 0.5)) {
			// 4. NON-CRITICAL GREEDY
			LOGINF("[ISO] {}: has l3_occup_mb {} > {} -> isolate!"_format(taskID, l3_occup_mb, limit_space));
			if (n_isolated_apps < 2) {
				isolate_application(taskID, taskPID, itT);
				limit_task[taskID] = true;
			} else
				LOGINF("[ISO] There are no isolated CLOSes available --> remain in CLOS 1");
			//countCLOS = task_increase_clos_change_count(*taskCLOS);
		}
	}

	LOGINF("—————– STEP 5 —————–");
	if (idle == true) {
		LOGINF("IDLE INTERVAL {}"_format(idle_count));
		idle_count = idle_count - 1;
		if (idle_count == 0) {
			idle = false;
			idle_count = idleIntervals;
		}
	} else if ((!change_critical) && (critical_apps > 0) && (critical_apps < 4)) {
		// if there is no new critical app, modify mask if not done previously
		LOGINF("IPC total = {}"_format(ipcTotal));
		LOGINF("Expected IPC total = {}"_format(expectedIPCtotal));

		double UP_limit_IPC = expectedIPCtotal * 1.04;
		double LOW_limit_IPC = expectedIPCtotal * 0.96;
		double NCR_limit_IPC = ipc_NCR_prev * 0.96;
		double CR_limit_IPC = ipc_CR_prev * 0.96;


		if (ipcTotal > UP_limit_IPC) {
			LOGINF("New IPC is BETTER: IPCtotal {} > {}"_format(ipcTotal, UP_limit_IPC));
			LOGINF("New IPC is better or equal -> {} idle intervals"_format(idleIntervals));
		} else {
			if ((ipc_CR < CR_limit_IPC) && (ipc_NCR >= NCR_limit_IPC))
				LOGINF("WORSE CR IPC: CR {} < {} && NCR {} >= {}"_format(
						ipc_CR, CR_limit_IPC, ipc_NCR, NCR_limit_IPC));
			else if ((ipc_NCR < NCR_limit_IPC) && (ipc_CR >= CR_limit_IPC))
				LOGINF("WORSE NCR IPC: NCR {} < {} && CR {} >= {}"_format(
						ipc_NCR, NCR_limit_IPC, ipc_CR, CR_limit_IPC));
			else if ((ipc_CR < CR_limit_IPC) && (ipc_NCR < NCR_limit_IPC))
				LOGINF("BOTH IPCs are WORSE: CR {} < {} && NCR {} < {}"_format(
						ipc_CR, CR_limit_IPC, ipc_NCR, NCR_limit_IPC));
			else
				LOGINF("BOTH IPCs are EQUAL (NOT WORSE)");

			// Transitions switch-case
			switch (state) {
				case 1:
				case 2:
				case 3:
				case 7:
				case 8:
					if ((ipcTotal <= UP_limit_IPC) && (ipcTotal >= LOW_limit_IPC))
						state = 5;
					else if ((ipc_NCR < NCR_limit_IPC) && (ipc_CR >= CR_limit_IPC))
						state = 6;
					else if ((ipc_CR < CR_limit_IPC) && (ipc_NCR >= NCR_limit_IPC))
						state = 5;
					else
						state = 5;
					break;

				case 5:
				case 6:
					if ((ipcTotal <= UP_limit_IPC) && (ipcTotal >= LOW_limit_IPC))
						state = 8;
					else if ((ipc_NCR < NCR_limit_IPC) && (ipc_CR >= CR_limit_IPC))
						state = 7;
					else if ((ipc_CR < CR_limit_IPC) && (ipc_NCR >= NCR_limit_IPC))
						state = 8;
					else // NCR and CR worse
						state = 8;
					break;
			}

			// State actions switch-case
			uint64_t max = 0;
			uint64_t noncritical_apps = tasklist.size() - critical_apps;
			uint64_t limit_critical = (ways_MAX + 2) - noncritical_apps;
			uint64_t num_ways_CLOS_1 = __builtin_popcount(LinuxBase::get_cat()->get_cbm(1));
			uint64_t num_ways_CLOS_2 = __builtin_popcount(LinuxBase::get_cat()->get_cbm(2));
			uint64_t num_ways_CLOS_3 = __builtin_popcount(LinuxBase::get_cat()->get_cbm(3));
			uint64_t num_ways_CLOS_4 = __builtin_popcount(LinuxBase::get_cat()->get_cbm(4));
			uint64_t maskNonCrCLOS = LinuxBase::get_cat()->get_cbm(1);
			uint64_t maskCLOS2 = LinuxBase::get_cat()->get_cbm(2);
			uint64_t maskCLOS3 = LinuxBase::get_cat()->get_cbm(3);
			uint64_t maskCLOS4 = LinuxBase::get_cat()->get_cbm(4);

			switch (state) {
				case 5:
					LOGINF("NCR-- (Remove one shared way from CLOS with non-critical "
						   "apps)");
					if (num_ways_CLOS_1 > noncritical_apps) {
						maskNonCrCLOS = (maskNonCrCLOS >> 1) & mask_MAX;
						LinuxBase::get_cat()->set_cbm(1, maskNonCrCLOS);
					} else
						LOGINF("Non-critical apps. have reached limit space.");
					break;

				case 6:
					LOGINF("CR-- (Remove one shared way from CLOS with critical apps)");
					maskCLOS2 = (maskCLOS2 << 1) & mask_MAX;
					maskCLOS3 = (maskCLOS3 << 1) & mask_MAX;
					maskCLOS4 = (maskCLOS4 << 1) & mask_MAX;
					LinuxBase::get_cat()->set_cbm(2, maskCLOS2);
					LinuxBase::get_cat()->set_cbm(3, maskCLOS3);
					LinuxBase::get_cat()->set_cbm(4, maskCLOS4);
					LLC_ways_space = LLC_ways_space - 1;
					break;

				case 7:
					LOGINF("NCR++ (Add one shared way to CLOS with non-critical apps)");
					maskNonCrCLOS = (maskNonCrCLOS << 1) | mask_min_right;
					LinuxBase::get_cat()->set_cbm(1, maskNonCrCLOS);
					break;

				case 8:
					LOGINF("CR++ (Add one shared way to CLOS with critical apps)");
					if (critical_apps == 1)
						max = num_ways_CLOS_2;
					else if (critical_apps == 2)
						max = std::max(num_ways_CLOS_2, num_ways_CLOS_3);
					else if (critical_apps == 3) {
						max = std::max(num_ways_CLOS_2, num_ways_CLOS_3);
						max = std::max(max, num_ways_CLOS_4);
					}
					LOGINF("MAX = {}, limit_critical = {}"_format(max, limit_critical));

					if (max < limit_critical) {
						maskCLOS2 = (maskCLOS2 >> 1) | mask_min_left;
						maskCLOS3 = (maskCLOS3 >> 1) | mask_min_left;
						maskCLOS4 = (maskCLOS4 >> 1) | mask_min_left;
						LinuxBase::get_cat()->set_cbm(2, maskCLOS2);
						LinuxBase::get_cat()->set_cbm(3, maskCLOS3);
						LinuxBase::get_cat()->set_cbm(4, maskCLOS4);
						LLC_ways_space = LLC_ways_space + 1;
					} else
						LOGINF("Critical app(s). have reached limit space.");
					break;

				default:
					break;
			}
		}

		idle = true;
		uint64_t num_ways_CLOS_1 = __builtin_popcount(LinuxBase::get_cat()->get_cbm(1));
		uint64_t num_ways_CLOS_2 = __builtin_popcount(LinuxBase::get_cat()->get_cbm(2));
		uint64_t num_ways_CLOS_3 = __builtin_popcount(LinuxBase::get_cat()->get_cbm(3));
		uint64_t num_ways_CLOS_4 = __builtin_popcount(LinuxBase::get_cat()->get_cbm(4));

		LOGINF("CLOS 1 (non-CR) has mask {:#x} ({} ways)"_format(LinuxBase::get_cat()->get_cbm(1), num_ways_CLOS_1));
		LOGINF("CLOS 2 (CR)     has mask {:#x} ({} ways)"_format(LinuxBase::get_cat()->get_cbm(2), num_ways_CLOS_2));
		if (critical_apps > 1)
			LOGINF("CLOS 3 (CR)     has mask {:#x} ({} ways)"_format(LinuxBase::get_cat()->get_cbm(3), num_ways_CLOS_3));
		if (critical_apps > 2)
			LOGINF("CLOS 4 (CR)     has mask {:#x} ({} ways)"_format(LinuxBase::get_cat()->get_cbm(4), num_ways_CLOS_4));

		uint64_t maxways = std::max(num_ways_CLOS_2, num_ways_CLOS_3);
		maxways = std::max(maxways, num_ways_CLOS_4);
		int64_t aux_ns = (num_ways_CLOS_2 + num_ways_CLOS_1) - ways_MAX;
		int64_t num_shared_ways = (aux_ns < 0) ? 0 : aux_ns;
		LOGINF("Number of shared ways: {}"_format(num_shared_ways));
		assert(num_shared_ways >= 0);

	}

	LOGINF("Current state = {}"_format(state));
	LOGINF("IPC Total = {}"_format(ipcTotal));
	ipc_CR_prev = ipc_CR;
	ipc_NCR_prev = ipc_NCR;
	expectedIPCtotal = ipcTotal;
	prev_critical_apps = critical_apps;
	id_pid.clear();
	id_phase_change.clear();
	LLCoccup_critical.clear();
	LLCoccup_noncritical.clear();
	LLC_critical = 0;

} // apply
////////////////////////////////////////////////


}
} // cat::policy
