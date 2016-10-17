#include <iostream>
#include <vector>
#include "cpucounters.h"
#include "manager_pcm.hpp"


using std::string;
using std::to_string;
using std::vector;

using std::cout;
using std::cerr;
using std::endl;
using std::setw;


struct CoreEvent
{
	char name[256];
	uint64 value;
	uint64 msr_value;
	char * description;
};


PCM *m;
uint64 BeforeTime = 0, AfterTime = 0;
SystemCounterState SysBeforeState, SysAfterState;
std::vector<CoreCounterState> BeforeState, AfterState;
std::vector<SocketCounterState> DummySocketStates;
bool csv = true;


void pcm_build_event(const char *event_str, EventSelectRegister &reg, CoreEvent &event)
{
	const int EVENT_SIZE = 256;

	char *token, *subtoken, *saveptr1, *saveptr2;
	char name[EVENT_SIZE], *str1, *str2;
	int j, tmp;
	unsigned long long tmp2;

	reg.value = 0;
	reg.fields.usr = 1;
	reg.fields.os = 1;
	reg.fields.enable = 1;

	memset(name, 0, EVENT_SIZE);
	strncpy(name, event_str, EVENT_SIZE - 1);

	for (j = 1, str1 = name; ; j++, str1 = NULL)
	{
		token = strtok_r(str1, "/", &saveptr1);
		if (token == NULL)
			break;

		printf("%d: %s\n", j, token);

		if(strncmp(token,"cpu", 3) == 0)
			continue;

		for (str2 = token; ; str2 = NULL)
		{
			tmp = -1;
			subtoken = strtok_r(str2, ",", &saveptr2);
			if (subtoken == NULL)
				break;
			if (sscanf(subtoken, "event=%i", &tmp) == 1)
				reg.fields.event_select = tmp;
			else if (sscanf(subtoken, "umask=%i", &tmp) == 1)
				reg.fields.umask = tmp;
			else if (strcmp(subtoken, "edge") == 0)
				reg.fields.edge = 1;
			else if (sscanf(subtoken, "any=%i", &tmp) == 1)
				reg.fields.any_thread = tmp;
			else if (sscanf(subtoken, "inv=%i", &tmp) == 1)
				reg.fields.invert = tmp;
			else if (sscanf(subtoken, "cmask=%i", &tmp) == 1)
				reg.fields.cmask = tmp;
			else if (sscanf(subtoken, "in_tx=%i", &tmp) == 1)
				reg.fields.in_tx = tmp;
			else if (sscanf(subtoken, "in_tx_cp=%i", &tmp) == 1)
				reg.fields.in_txcp = tmp;
			else if (sscanf(subtoken, "pc=%i", &tmp) == 1)
				reg.fields.pin_control = tmp;
			else if (sscanf(subtoken, "offcore_rsp=%llx", &tmp2) == 1)
			{
				// if(idx >= 2)
				// 	throw std::runtime_error("offcore_rsp must specify in first or second event only. idx=" + idx);
				event.msr_value = tmp2;
			}
			else if (sscanf(subtoken,"name=%255s",event.name) == 1)
			{}
			else
				throw std::runtime_error(string("Event '") + subtoken + "' is not supported. See the list of supported events");
		}
	}
	event.value = reg.value;
}


void pcm_setup(vector<string> str_events)
{
	CoreEvent           events[MAX_EVENTS];
	EventSelectRegister regs[MAX_EVENTS];

	PCM::ExtendedCustomCoreEventDescription conf;

	// Get PCM handler
	m = PCM::getInstance();

	if (str_events.size() > MAX_EVENTS)
		throw std::runtime_error("At most " + to_string(MAX_EVENTS) + " events are allowed");

	// Build events
	for (size_t i = 0; i < str_events.size(); i++)
		pcm_build_event(str_events[i].c_str(), regs[i], events[i]);

	// Prepare conf
	conf.fixedCfg = NULL; // default
	conf.nGPCounters = 4;
	conf.gpCounterCfg = regs;
	conf.OffcoreResponseMsrValue[0] = events[0].msr_value;
	conf.OffcoreResponseMsrValue[1] = events[1].msr_value;

	PCM::ErrorCode status = m->program(PCM::EXT_CUSTOM_CORE_EVENTS, &conf);
	switch (status)
	{
		case PCM::Success:
			break;

		case PCM::MSRAccessDenied:
			cerr << "Access to Intel(r) Performance Counter Monitor has denied (no MSR or PCI CFG space access)." << endl;
			exit(EXIT_FAILURE);

		case PCM::PMUBusy:
			cerr << "Access to Intel(r) Performance Counter Monitor has denied (Performance Monitoring Unit is occupied by other application). Try to stop the application that uses PMU." << endl;
			cerr << "Alternatively you can try to reset PMU configuration at your own risk. Try to reset? (y/n)" << endl;
			char yn;
			std::cin >> yn;
			if ('y' == yn)
			{
				m->resetPMU();
				cerr << "PMU configuration has been reset. Try to rerun the program again." << endl;
			}
			exit(EXIT_FAILURE);

		default:
			cerr << "Access to Intel(r) Performance Counter Monitor has been denied (Unknown error)." << endl;
			exit(EXIT_FAILURE);
	}

	cerr << "\nDetected "<< m->getCPUBrandString() << " \"Intel(r) microarchitecture codename "<<m->getUArchCodename()<<"\""<<endl;
}


template <class IntType>
inline std::string unit_format(IntType n)
{
    char buffer[1024];
    if (n <= 9999ULL)
    {
        sprintf(buffer, "%4d  ", int32(n));
        return buffer;
    }
    if (n <= 9999999ULL)
    {
        sprintf(buffer, "%4d K", int32(n / 1000ULL));
        return buffer;
    }
    if (n <= 9999999999ULL)
    {
        sprintf(buffer, "%4d M", int32(n / 1000000ULL));
        return buffer;
    }
    if (n <= 9999999999999ULL)
    {
        sprintf(buffer, "%4d G", int32(n / 1000000000ULL));
        return buffer;
    }
    sprintf(buffer, "%4d T", int32(n / (1000000000ULL * 1000ULL)));
    return buffer;
}


template <class StateType>
void print_custom_stats(const StateType &BeforeState, const StateType &AfterState, std::ostream &out, bool use_csv,  uint64 txn_rate = 1)
{
	uint64 cycles = getCycles(BeforeState, AfterState);
	uint64 instr = getInstructionsRetired(BeforeState, AfterState);

	if (!use_csv)
	{
		out << setw(10) << double(instr)/double(cycles);
		if(txn_rate == 1)
		{
			out << setw(14) << unit_format(instr);
			out << setw(11) << unit_format(cycles);
		}
		else
		{
			out << setw(14) << double(instr)/double(txn_rate);
			out << setw(11) << double(cycles)/double(txn_rate);
		}
	}
	else
	{
		out << double(instr)/double(cycles) << ",";
		out << double(instr)/double(txn_rate) << ",";
		out << double(cycles)/double(txn_rate) << ",";
	}

	for (int i = 0; i < MAX_EVENTS; ++i)
	{
		if(!use_csv)
		{
			out << setw(10);
			if(txn_rate == 1)
				out << unit_format(getNumberOfCustomEvents(i, BeforeState, AfterState));
			else
				out << double(getNumberOfCustomEvents(i, BeforeState, AfterState))/double(txn_rate);
		}
		else
		{
			out << double(getNumberOfCustomEvents(i, BeforeState, AfterState)) / double(txn_rate);
			if (i < MAX_EVENTS - 1)
				out << ",";
		}
	}
	out << endl;
}


void pcm_before()
{
	BeforeTime = m->getTickCount();
	m->getAllCounterStates(SysBeforeState, DummySocketStates, BeforeState);
}


void pcm_after(std::ostream &out)
{
	const size_t ncores = m->getNumCores();
	bool use_csv = out.rdbuf() != cout.rdbuf();
	AfterTime = m->getTickCount();
	m->getAllCounterStates(SysAfterState, DummySocketStates, AfterState);

	for(size_t i = 0; i < ncores ; ++i)
	{
		if (!m->isCoreOnline(i))// == false || (show_partial_core_output && ycores.test(i) == false))
			continue;

		if (use_csv)
			out << AfterTime - BeforeTime << "," << i << ",";
		else
			out << " " << setw(3) << i << "   " << setw(2) ;
		print_custom_stats(BeforeState[i], AfterState[i], out, use_csv);
	}
}


vector<Stats> pcm_after(const vector<uint32_t> &cores)
{
	auto res = vector<Stats>();

	AfterTime = m->getTickCount();
	m->getAllCounterStates(SysAfterState, DummySocketStates, AfterState);
	for (const auto &core : cores)
	{
		if (!m->isCoreOnline(core))
			throw std::runtime_error("Core " + to_string(core) + " is not online");

		Stats stats =
		{
			.ms = AfterTime - BeforeTime,
			.cycles = getCycles(BeforeState[core], AfterState[core]),
			.instructions = getInstructionsRetired(BeforeState[core], AfterState[core]),
		};
		for (int i = 0; i < MAX_EVENTS; ++i)
			stats.event[i] = getNumberOfCustomEvents(i, BeforeState[core], AfterState[core]);

		res.push_back(stats);
	}
	return res;
}


void pcm_clean()
{
	PCM::getInstance()->cleanup();
}


void Stats::print(std::ostream &out, bool csv_format) const
{
	const double ipc = double(instructions) / double(cycles);
	if (csv_format)
	{
		out << ipc << ",";
		out << instructions << ",";
		out << cycles << ",";
		out << ms << ",";
	}
	else
	{
		out << setw(10) << ipc;
		out << setw(14) << unit_format(instructions);
		out << setw(11) << unit_format(cycles);
		out << setw(11) << ms;
	}

	for (int i = 0; i < MAX_EVENTS; ++i)
	{
		if(csv_format)
		{
			out << event[i];
			if (i < MAX_EVENTS - 1)
				out << ",";
		}
		else
		{
			out << setw(10);
			out << unit_format(event[i]);
		}
	}
	out << endl;
}