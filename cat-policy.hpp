#pragma once

#include <cassert>
#include <functional>
#include <unordered_map>
#include <vector>

#include "cat.hpp"
#include "task.hpp"

namespace cat
{


const uint32_t min_num_ways = 2;
const uint32_t max_num_ways = 20;
const uint32_t complete_mask = ~(-1U << max_num_ways);


namespace policy
{


// Base class that does nothing
class Base
{
	protected:

	std::shared_ptr<CAT> cat;

	public:

	Base() = default;

	void set_cat(std::shared_ptr<CAT> _cat)    { cat = _cat; }
	std::shared_ptr<CAT> get_cat()             { return cat; }
	const std::shared_ptr<CAT> get_cat() const { return cat; }

	void set_cbms(const cbms_t &cbms)
	{
		assert(cat->get_max_closids() >= cbms.size());
		for(size_t clos = 0; clos < cbms.size(); clos++)
			get_cat()->set_cbm(clos, cbms[clos]);
	}

	virtual ~Base() = default;

	// Derived classes should perform their operations here.
	// The base class does nothing by default.
	virtual void apply(uint64_t, const tasklist_t &) {}
};



}} // cat::policy
