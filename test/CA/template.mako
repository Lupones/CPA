<%include file="applications.mako"/>
<%include file="instr_60s_500ms.mako"/>

cos:
  - schemata: 0xfffff
  - schemata: 0xfffff
  - schemata: 0xfffff


tasks:
  % for app in apps:
  - app: *${app}
    max_instr: *${app}_mi
    initial_clos: 1
  % endfor


cat_policy: 
    kind: ca
    every: 1 
    stats: interval
    firstInterval: 10

cmd:
    ti: 0.5
    mi: 20000
    event: ["instructions,cycles,mem_load_uops_retired.l3_hit,mem_load_uops_retired.l3_miss,cycle_activity.stalls_ldm_pending,intel_cqm/llc_occupancy/"]
    cat-impl: linux
    cpu-affinity: [3]
