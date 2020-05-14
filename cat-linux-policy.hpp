#pragma once

#include "cat-policy.hpp"
#include "cat-linux.hpp"


#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/max.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/stats.hpp>
#include <boost/accumulators/statistics/rolling_window.hpp>
#include <boost/accumulators/statistics/rolling_variance.hpp>
#include <set>
#include <deque>

namespace cat
{


namespace policy
{

namespace acc = boost::accumulators;


class LinuxBase : public Base
{
      public:

      LinuxBase() = default;
      virtual ~LinuxBase() = default;

      // Safely cast CAT to LinuxCat
      std::shared_ptr<CATLinux> get_cat()
      {
          auto ptr = std::dynamic_pointer_cast<CATLinux>(cat);
          if (ptr)
              return ptr;
          else
              throw_with_trace(std::runtime_error("Linux CAT implementation required"));
      }

      // Derived classes should perform their operations here. This base class does nothing by default.
      virtual void apply(uint64_t, const tasklist_t &) {}
};


// No partition policy
class NoPart: public Base
{
    protected:
	std::shared_ptr<CAT> catLinux = std::make_shared<CATLinux>();
    uint64_t every = -1;
    std::string stats = "total";

	double expected_IPC = 0;

    public:
    virtual ~NoPart() = default;
    NoPart(uint64_t _every, std::string _stats) : every(_every), stats(_stats){}
    virtual void apply(uint64_t, const tasklist_t &) override;
};
typedef NoPart NP;


class CriticalAware: public LinuxBase
{

    protected:
    uint64_t every = -1;
    uint64_t firstInterval = 1;

    //Masks of CLOS
    uint64_t maskCrCLOS = 0xfffff;
    uint64_t num_ways_CLOS_2 = 20;
    uint64_t maskNonCrCLOS = 0xfffff;
    uint64_t num_ways_CLOS_1 = 20;

    int64_t num_shared_ways = 0;

    //Control of the changes made in the masks
    uint64_t state = 0;
    double expectedIPCtotal = 0;
    double ipc_CR_prev = 0;
    double ipc_NCR_prev = 0;

    double mpkiL3Mean = 0;
	double stdmpkiL3Mean = 0;

    bool firstTime = true;

    uint64_t IDLE_INTERVALS = 5;
    uint64_t idle_count = IDLE_INTERVALS;
    bool idle = false;

	// Define accumulators
	typedef acc::accumulator_set<
		double, acc::stats<
			acc::tag::rolling_mean,
			acc::tag::rolling_variance
		>
	>
	ca_accum_t;

	ca_accum_t macc;

    //vector to store if task is assigned to critical CLOS
	typedef std::tuple<pid_t, uint64_t> pair_t;
    std::vector<pair_t> taskIsInCRCLOS;
	std::vector<pair_t> pid_CPU;

	// number of times a task has been critical
	std::map<pid_t,uint64_t> frequencyCritical;

    public:

	//typedef std::tuple<pid_t, uint64_t> pair_t

    CriticalAware(uint64_t _every, uint64_t _firstInterval) : every(_every), firstInterval(_firstInterval), macc(acc::tag::rolling_window::window_size = 10u) {}

    virtual ~CriticalAware() = default;

    //configure CAT
    void reset_configuration(const tasklist_t &);

	// calculate median of vector of tuples
	typedef std::tuple<pid_t, double> pairD_t;
	double medianV(std::vector<pairD_t> &vec);

	virtual void apply(uint64_t current_interval, const tasklist_t &tasklist);

};
typedef CriticalAware CA;

class CriticalPhaseAware: public LinuxBase
{
    protected:
    uint64_t every = -1;
    uint64_t firstInterval = 1;
	uint64_t idleIntervals = 1;
	double ipcLow = 0;
	double ipcMedium = 0;
	double icov = 1;
	double hpkil3Limit = 0;

    /* Masks and number of ways of CLOS */
	// FULL CACHE
	uint64_t mask_MAX = 0xfffff;
	uint64_t ways_MAX = 20;
	uint64_t mask_min_right = 0x00001;
	uint64_t mask_min_left = 0x80000;

	// 1 CRITICAL APPLICATION
	// 60% ways critical, 50% ways non-critical
	uint64_t mask_CRCLOS_1 = 0xfff00;
	uint64_t mask_NCRCLOS_1 = 0x003ff;

	// 2 CRITICAL APPLICATIONS
	// 65% ways critical, 45% ways non-critical
	uint64_t mask_CRCLOS_2 = 0xfff80;
	uint64_t mask_NCRCLOS_2 = 0x001ff;

	// 3 CRITICAL APPLICATIONS
	// 70% ways critical, 40% ways non-critical
	uint64_t mask_CRCLOS_3 = 0xfffc0;
	uint64_t mask_NCRCLOS_3 = 0x000ff;

	// Threshold to consider non-critical app as greedy
	// 15% of ways_MAX
	double limit_space_ncr = ways_MAX * 0.15;

	// SQUANDERER and NON-CRITICAL GREEDY APPLICATIONS
	// CLOSes 5 and 6
	// 10% ways to each one,
	// overlapping with non-critical ways
	uint64_t mask_iso_1 = 0x00003;
	uint64_t mask_iso_2 = 0x0000f;
	std::vector<uint32_t> id_isolated;
	uint64_t n_isolated_apps = 0;
	std::vector<uint64_t> isolated_closes = {5, 6};

	// Window size of MPKIL3 valies
	uint64_t windowSize = 10;

	// Bool variable to state if cache is partitioned for the first time
	bool firstTime = true;

    // Control of the changes made in the masks
    uint64_t state = 0;
    double expectedIPCtotal = 0;
    double ipc_CR_prev = 0;
    double ipc_NCR_prev = 0;

	// Limit outlier calculation variables
    double mpkiL3Mean = 0;
	double stdmpkiL3Mean = 0;

	// Isolation mechanism variables

	// Critical applications variables
	uint32_t critical_apps = 0;
	std::map<uint64_t,double> LLCoccup_critical;
	//std::map<uint64_t,double> LLCoccup_noncritical;
	double LLC_critical = 0;
	double LLC_ways_space = 0;
	std::set<uint32_t> CLOS_critical = {2, 3, 4};
	uint64_t prev_critical_apps = 0;

	// Dictionary holding up to windowsize[taskID] last MPKIL3 valid (non-spike) values
    std::map<uint32_t, std::deque<double>> valid_mpkil3;

    // Dictionaries holdind phase info for each task
	//std::map<uint32_t, uint64_t> ipc_phase_count;
	std::map<uint32_t, uint64_t> ipc_phase_duration;
	// Dictionary holding sum of MPKIL3 of each application during a given phase
	std::map<uint32_t, double> ipc_sumXij;

	// Dictionary and bool variable to indicate in critical app / space has been reduced
	std::map<uint32_t, uint64_t> limit_task;
   	bool limit = false;

	// Set to true if app has HPKIL3 low and high MPKIL3
	// i.e. bully or squaderer applications
	// In order for next interval to not contaminate
	// set of MPKIL3 values
	std::map<uint64_t, bool> excluded;

	// Idle variables
    uint64_t idle_count = idleIntervals;
    bool idle = false;

	// Define accumulators
    typedef acc::accumulator_set<
        double, acc::stats<
            acc::tag::mean,
            acc::tag::variance,
            acc::tag::count
        >
    >
    ca_accum_t;

    //vector to store if task is assigned to critical CLOS
	typedef std::tuple<uint32_t, uint64_t> pair_t;
    typedef std::tuple<uint32_t, double> pairD_t;
	typedef std::tuple<uint32_t, pid_t> pair32P_t;
    std::vector<pair_t> taskIsInCRCLOS;
	std::vector<pair32P_t> id_pid;
	std::vector<pairD_t> LLCoccup_noncritical;

	/* Comparison function to sort the vector elements
	// by second element of tuples
	bool sortbysec(const std::tuple<uint32_t, double>& a,
               const std::tuple<uint32_t, double>& b)
	{
    	return (std::get<1>(a) > std::get<1>(b));
	}*/


    public:

    CriticalPhaseAware(uint64_t _every, uint64_t _firstInterval, uint64_t _idleIntervals, double _ipcMedium, double _ipcLow, double _icov, double _hpkil3Limit) : every(_every), firstInterval(_firstInterval), idleIntervals(_idleIntervals), ipcLow(_ipcLow), ipcMedium(_ipcMedium), icov(_icov), hpkil3Limit(_hpkil3Limit) {}

    virtual ~CriticalPhaseAware() = default;

    //configure CAT
	void update_configuration(std::vector<pair_t> v, std::vector<pair_t> status, uint64_t num_critical_old, uint64_t num_critical_new);
	void include_application(uint32_t taskID, pid_t taskPID, std::vector<pair_t>::iterator it, uint64_t CLOSvalue);
	void isolate_application(uint32_t taskID, pid_t taskPID, std::vector<pair_t>::iterator it);
	void divide_half_ways_critical(uint64_t clos, uint32_t cr_apps);
	void divide_3_critical(uint64_t clos, bool limitDone);
	virtual void apply(uint64_t current_interval, const tasklist_t &tasklist);

};
typedef CriticalPhaseAware CPA;

}} // cat::policy
