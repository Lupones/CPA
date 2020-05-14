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
    kind: cpa
    every: 1 
    idleIntervals: 5
    firstInterval: 10
    ipcLow: 0.60
    ipcMedium: 1.30
    icov: 0.20
    hpkil3Limit: 0.5

cmd:
    ti: 0.5
    mi: 20000
    event: ["instructions,cycles,mem_load_uops_retired.l3_hit,mem_load_uops_retired.l3_miss,cycle_activity.stalls_ldm_pending,intel_cqm/llc_occupancy/"]
    cat-impl: linux
    cpu-affinity: [3]
