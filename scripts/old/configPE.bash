# MASKS=(3 f 3f ff fff ffff fffff)
# MASKS=(3 7 f fffff)
MASKS=(fffff)
INT=0.5 # Interval size in seconds
MAX=2000 # Max number of intervals
INI_REP=0
MAX_REP=1

function join_by { local IFS="$1"; shift; echo "$*"; }
