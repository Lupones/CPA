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

class CriticalAwareV4: public LinuxBase
{
    protected:
    uint64_t every = -1;
    uint64_t firstInterval = 1;
	uint64_t IDLE_INTERVALS = 1;
	double ipc_threshold = 0;
	double ipc_ICOV_threshold = 1;

    //Masks of CLOS
	uint64_t num_ways_CLOS1 = 20;
    uint64_t num_ways_CLOS2 = 20;
	uint64_t num_ways_CLOS4 = 20;
	uint64_t num_ways_CLOS3 = 20;
 	uint64_t mask_CLOS1 = 0xfffff;
    uint64_t mask_CLOS2 = 0xfffff;
	uint64_t mask_CLOS3 = 0xfffff;
	uint64_t mask_CLOS4 = 0xfffff;

	uint64_t prev_critical_apps = 0;
    //int64_t num_shared_ways = 0;

	uint64_t windowSize = 10;

	bool firstTime = true;

    //Control of the changes made in the masks
    //uint64_t state = 0;
    double expectedIPCtotal = 0;
    double ipc_CR_prev = 0;
    double ipc_NCR_prev = 0;

	// Limit outlier calculation variables
    double mpkiL3Mean = 0;
	double stdmpkiL3Mean = 0;

	// Isolation mechanism variables
	uint64_t CLOS_isolated = 5;
    uint64_t n_isolated_apps = 0;
    uint64_t mask_isolated = 0x00007;
	std::vector<uint64_t> free_closes = {5, 6, 7};
	std::map<uint64_t, uint64_t> clos_mask = {
          { 5, 0x00007 },
          { 6, 0x00038 },
          { 7, 0x001c0 }
	};

	// dictionary holding up to windowsize[taskID] last MPKIL3 valid (non-spike) values
    std::map<uint32_t, std::deque<double>> valid_mpkil3;

    // dictionaries holdind phase info for each task
	std::map<uint32_t, uint64_t> ipc_phase_count;
    std::map<uint32_t, uint64_t> ipc_phase_duration;
	std::map<uint32_t, uint64_t> bully_counter;

    // dictionary holding sum of MPKIL3 of each application during a given phase
	std::map<uint32_t, double> ipc_sumXij;

	// Set to true if app has HPKIL3 low and high MPKIL3
	// In order for next interval to not contaminate
	// set of MPKIL3 values
	std::map<uint64_t, bool> excluded;
	std::map<uint64_t, bool> ipc_phase_change;
	std::map<uint64_t, bool> ipc_icov;
	std::map<uint64_t, bool> ipc_good;

    uint64_t idle_count = IDLE_INTERVALS;
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

	std::map<uint64_t, double> prev_ipc;

    //vector to store if task is assigned to critical CLOS
	typedef std::tuple<uint32_t, uint64_t> pair_t;
    typedef std::tuple<uint32_t, double> pairD_t;
	typedef std::tuple<uint32_t, pid_t> pair32P_t;
    std::vector<pair_t> taskIsInCRCLOS;
	std::vector<pair_t> status;
	std::vector<pair32P_t> id_pid;
	std::vector<uint32_t> id_isolated;

    public:

	//typedef std::tuple<pid_t, uint64_t> pair_t

    CriticalAwareV4(uint64_t _every, uint64_t _firstInterval, uint64_t _IDLE_INTERVALS, double _ipc_threshold, double _ipc_ICOV_threshold) : every(_every), firstInterval(_firstInterval),IDLE_INTERVALS(_IDLE_INTERVALS), ipc_threshold(_ipc_threshold), ipc_ICOV_threshold(_ipc_ICOV_threshold) {}

    virtual ~CriticalAwareV4() = default;

    //configure CAT
	void update_configuration(std::vector<pair_t> v, std::vector<pair_t> status, uint64_t num_critical_old, uint64_t num_critical_new);
	void include_application(uint32_t taskID, pid_t taskPID, std::vector<pair_t>::iterator it, uint64_t CLOSvalue);
	void isolate_application(uint32_t taskID, pid_t taskPID, std::vector<pair_t>::iterator it);
	virtual void apply(uint64_t current_interval, const tasklist_t &tasklist);

};
typedef CriticalAwareV4 CAV4;

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

    // Masks and number of ways of CLOS
	uint64_t maskCLOS2 = 0xfffff;
	uint64_t maskCLOS3 = 0xfffff;
	uint64_t maskCLOS4 = 0xfffff;
    uint64_t num_ways_CLOS_2 = 20;
	uint64_t num_ways_CLOS_3 = 20;
	uint64_t num_ways_CLOS_4 = 20;
    uint64_t maskNonCrCLOS = 0xfffff;
    uint64_t num_ways_CLOS_1 = 20;
	uint64_t prev_critical_apps = 0;
    int64_t num_shared_ways = 0;

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
    std::vector<uint32_t> id_isolated;
	uint64_t n_isolated_apps = 0;
	std::vector<uint64_t> isolated_closes = {5, 6};
	std::map<uint64_t, uint64_t> clos_mask = {
          { 5, 0x00003 },
          { 6, 0x00003 },
          { 7, 0x000ff },
		  { 8, 0x000ff },
	};

	// Critical applications variables
	uint32_t critical_apps = 0;
	std::map<uint64_t,double> LLCoccup_critical;
	std::set<uint32_t> CLOS_critical = {2, 3, 4};

	// Dictionary holding up to windowsize[taskID] last MPKIL3 valid (non-spike) values
    std::map<uint32_t, std::deque<double>> valid_mpkil3;

    // Dictionaries holdind phase info for each task
	std::map<uint32_t, uint64_t> ipc_phase_count;
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

    public:

    CriticalPhaseAware(uint64_t _every, uint64_t _firstInterval, uint64_t _idleIntervals, double _ipcMedium, double _ipcLow, double _icov, double _hpkil3Limit) : every(_every), firstInterval(_firstInterval), idleIntervals(_idleIntervals), ipcLow(_ipcLow), ipcMedium(_ipcMedium), icov(_icov), hpkil3Limit(_hpkil3Limit) {}

    virtual ~CriticalPhaseAware() = default;

    //configure CAT
	void update_configuration(std::vector<pair_t> v, std::vector<pair_t> status, uint64_t num_critical_old, uint64_t num_critical_new);
	void include_application(uint32_t taskID, pid_t taskPID, std::vector<pair_t>::iterator it, uint64_t CLOSvalue);
	void isolate_application(uint32_t taskID, pid_t taskPID, std::vector<pair_t>::iterator it);
	void divide_1_critical(uint64_t clos);
	void divide_2_critical(uint64_t clos);
	void divide_3_critical(uint64_t clos, bool limitDone);
	virtual void apply(uint64_t current_interval, const tasklist_t &tasklist);

};
typedef CriticalPhaseAware CPA;





class CriticalAwareV2: public LinuxBase
{
	protected:
    uint64_t every = -1;
    uint64_t firstInterval = 1;
	uint64_t windowSize = 4;
	std::string outlierMethod="Schwetman";
	uint64_t effectIntervals = 1;
	std::string partitionScheme = "ca";

	//uint64_t effect_count = effectIntervals;

    // Masks of CLOS
    uint64_t maskCrCLOS = 0xfffff;
    uint64_t num_ways_CLOS_2 = 20;
    uint64_t maskNonCrCLOS = 0xfffff;
    uint64_t num_ways_CLOS_1 = 20;
	int64_t num_shared_ways = 0;
	uint64_t prev_critical_apps = 0;

    // Control of the changes made in the masks
    uint64_t state = 0;
    double expectedIPCtotal = 0;
    double ipc_CR_prev = 0;
    double ipc_NCR_prev = 0;

	// Flags
    bool firstTime = true;
	bool idle = false;
	bool effectTime = false;

	// IDLE control variables
    //uint64_t IDLE_INTERVALS = 5;
    uint64_t idle_count = effectIntervals;

    // vector to store if task is assigned to critical CLOS
    typedef std::tuple<uint32_t, uint64_t> pair_t;
	typedef std::tuple<uint32_t, double> pairD_t;
	typedef std::tuple<uint32_t, pid_t> pair32P_t;
	typedef std::tuple<std::string, double> pairSD_t;
	//std::set<double> all_mpkil3;
    std::vector<pair_t> taskIsInCRCLOS;
    std::vector<pair_t> pid_CPU;
	std::vector<pairD_t> v_mpkil3_prev;
	std::vector<pair32P_t> id_pid;
	std::vector<uint32_t> id_isolated;

	// number of times a task has been critical
    std::map<pid_t,uint64_t> frequencyCritical;

	bool reset = false;

	std::map<uint64_t, double> non_critical = {
          { 0, 1 },
          { 1, 1 },
          { 2, 1 },
          { 3, 1 },
          { 4, 1 },
          { 5, 1 },
          { 6, 1 },
          { 7, 1 }
	};

	std::map<uint64_t, double> clear_mpkil3 = {
		{ 0, 0 },
        { 1, 0 },
        { 2, 0 },
        { 3, 0 },
        { 4, 0 },
        { 5, 0 },
        { 6, 0 },
        { 7, 0 }
     };

	// Map of windowSizes
	std::map<uint64_t, double> windowSizeM = {
          { 0, windowSize },
          { 1, windowSize },
          { 2, windowSize },
          { 3, windowSize },
          { 4, windowSize },
          { 5, windowSize },
          { 6, windowSize },
          { 7, windowSize }
    };



	// Table with values of Kn
	std::map<uint64_t, double> kn_table = {
		{ 5, 1.65798 },
		{ 6, 1.28351 },
		{ 7, 1.51475 },
		{ 8, 1.32505 },
		{ 9, 1.50427 },
		{ 10, 1.31212 },
		{ 11, 1.45768 },
		{ 12, 1.32968 },
		{ 13, 1.45268 },
		{ 14, 1.32353 },
		{ 15, 1.42975 },
		{ 16, 1.33318 },
		{ 17, 1.42684 },
		{ 18, 1.32959 },
		{ 19, 1.41322 },
		{ 20, 1.33568 },
		{ 21, 1.41132 },
		{ 22, 1.33333 },
		{ 23, 1.4023 },
		{ 24, 1.33753 },
		{ 25, 1.40096 },
		{ 26, 1.33587 },
		{ 27, 1.39455 },
		{ 28, 1.33894 },
		{ 29, 1.39355 },
		{ 30, 1.3377 },
		{ 31, 1.38876 },
		{ 32, 1.34004 },
		{ 33, 1.38799 },
		{ 34, 1.33909 },
		{ 35, 1.38428 },
		{ 36, 1.34092 },
		{ 37, 1.38367 },
		{ 38, 1.34017 },
		{ 39, 1.38071 },
		{ 40, 1.34165 },
		{ 41, 1.38021 },
		{ 42, 1.34104 },
		{ 43, 1.37779 },
		{ 44, 1.34226 },
		{ 45, 1.37737 },
		{ 46, 1.34175 },
		{ 47, 1.37536 },
		{ 48, 1.34278 },
		{ 49, 1.37501 },
		{ 50, 1.34235 },
		{ 51, 1.37331 },
		{ 52, 1.34322 },
		{ 53, 1.37301 },
		{ 54, 1.34285 },
		{ 55, 1.37156 },
		{ 56, 1.34361 },
		{ 57, 1.3713 },
		{ 58, 1.34329 },
		{ 59, 1.37004 },
		{ 60, 1.34394 },
		{ 61, 1.36981 },
		{ 62, 1.34366 },
		{ 63, 1.36871 },
		{ 64, 1.34424 },
		{ 65, 1.36851 },
		{ 66, 1.34399 },
		{ 67, 1.36754 },
		{ 68, 1.3445 },
		{ 69, 1.36737 },
        { 70, 1.34429 },
		{ 71, 1.3665 },
		{ 72, 1.34474 },
		{ 73, 1.36635 },
		{ 74, 1.34454 },
		{ 75, 1.36557 },
		{ 76, 1.34495 },
		{ 77, 1.36543 },
		{ 78, 1.34478 },
		{ 79, 1.36474 },
		{ 80, 1.34514 }
    };


	// Maximum value of MPKI-L3 in the current interval
    double max_mpkil3 = 0;

    uint64_t CLOS_isolated = 3;
	uint64_t n_isolated_apps = 0;
	uint64_t mask_isolated = 0x00003;

	//dictinary holding previous value of critical apps
	std::map<pid_t, double> ipc_critical_prev;
	bool false_critical_app = false;
	//uint32_t excluded_application;
	double excluded_application_ipc;

	// dictionary holding deque with 3 last MPKIL3 values for each task
	//std::map<uint32_t, std::deque<double>> deque_mpkil3;

	// dictionary holding up to windowsize[taskID] last MPKIL3 valid (non-spike) values
	std::map<uint32_t, std::deque<double>> valid_mpkil3;

	// dictionaries holdind phase info for each task
	std::map<uint32_t, uint64_t> phase_count;
	std::map<uint32_t, uint64_t> phase_duration;

	// dictionary holding sum of MPKIL3 of each application during a given phase
	std::map<uint32_t, double> sumXij;

	// number of times consecutive critical_apps = 0 detected
	uint64_t num_no_critical = 0;

	// Define accumulators
    typedef acc::accumulator_set<
        double, acc::stats<
            acc::tag::mean,
            acc::tag::variance,
			acc::tag::count
        >
    >
    ca_accum_t;

	// Dictionary of accumulators to detect spike values in the mpkil3
	//std::map<uint32_t, ca_accum_t> sacc;

    public:

	CriticalAwareV2(uint64_t _every, uint64_t _firstInterval, uint64_t _windowSize, std::string _outlierMethod, uint64_t _effectIntervals, std::string _partitionScheme) : every(_every), firstInterval(_firstInterval), windowSize(_windowSize), outlierMethod(_outlierMethod), effectIntervals(_effectIntervals), partitionScheme(_partitionScheme){}

    virtual ~CriticalAwareV2() = default;


	double medianV(std::set<double> vec);

    //configure CAT
    void update_configuration(std::vector<pair_t> v, std::vector<pair_t> status, uint64_t num_critical_old, uint64_t num_critical_new);

    virtual void apply(uint64_t current_interval, const tasklist_t &tasklist);

};
typedef CriticalAwareV2 CAV2;


//-----------------------------------------------------------------------------
// Aux functions
//-----------------------------------------------------------------------------


void tasks_to_closes(catlinux_ptr_t cat, const tasklist_t &tasklist, const clusters_t &clusters);
std::string cluster_to_tasks(const Cluster &cluster, const tasklist_t &tasklist);


class ClusteringBase: public LinuxBase
{
	public:

	class CouldNotCluster : public std::runtime_error
	{
		public:
		CouldNotCluster(const std::string &msg) : std::runtime_error(msg) {};
	};

	ClusteringBase() = default;
	virtual ~ClusteringBase() = default;

	virtual clusters_t apply(const tasklist_t &tasklist);

};
typedef std::shared_ptr<ClusteringBase> ClusteringBase_ptr_t;


class Cluster_SF: public ClusteringBase
{
	public:

	int m;
	std::vector<int> sizes;

	Cluster_SF(const std::vector<int> &_sizes) : sizes(_sizes) {}
	virtual ~Cluster_SF() = default;

	virtual clusters_t apply(const tasklist_t &tasklist) override;
};


class Cluster_KMeans: public ClusteringBase
{
	public:

	int num_clusters;
	int max_clusters;
	EvalClusters eval_clusters;
	std::string event;
	bool sort_ascending;

	Cluster_KMeans(int _num_clusters, int _max_clusters, EvalClusters _eval_clusters, std::string _event, bool _sort_ascending) :
			num_clusters(_num_clusters), max_clusters(_max_clusters),
			eval_clusters(_eval_clusters), event(_event),
			sort_ascending(_sort_ascending) {}
	virtual ~Cluster_KMeans() = default;

	virtual clusters_t apply(const tasklist_t &tasklist) override;
};


class DistributingBase
{
	public:

	int min_ways;
	int max_ways;

	DistributingBase()
	{
		auto info = cat_read_info();
		min_ways = info["L3"].min_cbm_bits;
		max_ways = __builtin_popcount(info["L3"].cbm_mask);
	}

	DistributingBase(int _min_ways, int _max_ways) : min_ways(_min_ways), max_ways(_max_ways) {}

	uint32_t cut_mask(uint32_t mask)
	{
		return mask & ~((uint32_t) -1 << max_ways);
	}

	virtual ~DistributingBase() = default;

	virtual cbms_t apply(const tasklist_t &, const clusters_t &) { return cbms_t(); };
};
typedef std::shared_ptr<DistributingBase> DistributingBase_ptr_t;


class Distribute_N: public DistributingBase
{
	int n;

	public:

	Distribute_N(int _n): n(_n) {}
	Distribute_N(int _min_ways, int _max_ways, int _n): DistributingBase(_min_ways, _max_ways), n(_n) {}
	virtual ~Distribute_N() = default;

	virtual cbms_t apply(const tasklist_t &, const clusters_t &clusters) override;
};


class Distribute_Static: public DistributingBase
{
	cbms_t masks;

	public:

	Distribute_Static(const cbms_t &_masks) : masks(_masks){}
	virtual ~Distribute_Static() = default;

	virtual cbms_t apply(const tasklist_t &, const clusters_t &) override { return masks; }
};


class Distribute_RelFunc: public DistributingBase
{
	bool invert_metric;

	public:

	Distribute_RelFunc() = default;
	Distribute_RelFunc(bool _invert_metric) : invert_metric(_invert_metric) {};
	Distribute_RelFunc(int _min_ways, int _max_ways, bool _invert_metric) :
			DistributingBase(_min_ways, _max_ways), invert_metric(_invert_metric) {};
	virtual ~Distribute_RelFunc() = default;

	virtual cbms_t apply(const tasklist_t &, const clusters_t &clusters) override;
};


class SquareWave: public LinuxBase
{
	bool is_down;

	public:

	class Wave
	{
		public:
		bool is_down;
		uint32_t interval;
		cbm_t up;
		cbm_t down;
		Wave() = default;
		Wave(uint32_t _interval, cbm_t _up, cbm_t _down) : is_down(false), interval(_interval), up(_up), down(_down) {}
	};

	std::vector<Wave> waves;
	ClusteringBase clustering;

	SquareWave() = delete;
	SquareWave(std::vector<Wave> _waves) : waves(_waves), clustering() {}

	virtual void apply(uint64_t current_interval, const tasklist_t &tasklist);
};


class ClusterAndDistribute: public LinuxBase
{

	uint32_t every;
	ClusteringBase_ptr_t clustering;
	DistributingBase_ptr_t distributing;

	public:

	ClusterAndDistribute() = delete;
	ClusterAndDistribute(uint32_t _every, ClusteringBase_ptr_t _clustering, DistributingBase_ptr_t _distributing) :
			every(_every), clustering(_clustering), distributing(_distributing) {}

	virtual void apply(uint64_t current_interval, const tasklist_t &tasklist);
	void show(const tasklist_t &tasklist, const clusters_t &clusters, const cbms_t &ways);
};

}} // cat::policy
