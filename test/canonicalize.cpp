#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <map>
#include <string>
#include <deque>
using namespace std;

struct inst {
    string addr;
    string branch_flag;
};

struct divergence {
    string div_addr;
    string div_value;
    string div_dir;
    string merge_addr;
    string merge_value;
    deque<struct inst> orig_branch;
    deque<struct inst> alt_branch;
    int count;
    int iter_count; // How many extra times around a loop?
};

struct index_div {
    string addr;
    string type;
    string value;
};

static void print_divergence (struct divergence& div)
{
    deque<struct inst>::iterator oiter;
    deque<struct inst>::iterator aiter;

    // Iteration count is only valid for loops 
    if (div.div_addr != div.merge_addr) div.iter_count = 0;

    printf ("%s ctrl_diverge %s orig_branch %s iter %d\n", div.div_addr.c_str(), 
	    div.div_value.c_str(), div.div_dir.c_str(), div.iter_count);
    for (oiter = div.orig_branch.begin(); oiter != div.orig_branch.end(); ++oiter) {
	printf ("%s ctrl_block_instrument_orig branch %s\n", oiter->addr.c_str(), 
		oiter->branch_flag.c_str());
    }
    for (aiter = div.alt_branch.begin(); aiter != div.alt_branch.end(); ++aiter) {
	printf ("%s ctrl_block_instrument_alt branch %s\n", aiter->addr.c_str(), 
		aiter->branch_flag.c_str());
    }
    printf ("%s ctrl_merge %s\n", div.merge_addr.c_str(), div.merge_value.c_str());
}

static void print_index_rw (struct index_div& rw)
{
    printf ("%s %s %s\n", rw.addr.c_str(), rw.type.c_str(), rw.value.c_str());
}

int main (int argc, char* argv[])
{
    char line[256];
    char addr[64], type[64], value[64], extra1[64], extra2[64], extra3[64], extra4[64];
    divergence div;
    bool is_dup = false, is_flipped = false, diverged = false;
    string last_diverge_addr, last_diverge_value;

    map<string, struct divergence>::iterator iter;
    map<string, struct divergence> divergences;
    map<string, struct index_div> indexes;
    map<pair<string,string>, struct divergence> divergence_exceptions;
    deque<struct inst>::iterator oiter;
    deque<struct inst>::iterator aiter;

    for (int i = 1; i < argc; i++) {
	FILE* file = fopen(argv[i], "r");
	if (file == NULL) {
	    fprintf (stderr, "Unable to open input file: %s\n", argv[i]);
	    return -1;
	}

	while (!feof(file)) {
	    if (fgets(line, sizeof(line), file)) {
	      if (sscanf(line, "%63s %63s %63s %63s %63s %63s %63s", addr, type, value, extra1, extra2, extra3, extra4) >= 3) { 
		    if (!strcmp(type, "ctrl_diverge")) {
			iter = divergences.find(addr);
			is_dup = (iter != divergences.end());
			diverged = false;
			if (is_dup) {
			    div = iter->second;
			    is_flipped = strcmp(extra2, div.div_dir.c_str());
			    div.count++;
			    if (!strcmp(addr,last_diverge_addr.c_str()) && !strcmp(value, last_diverge_value.c_str())) {
				div.iter_count ++;
			    }
			    oiter = div.orig_branch.begin();
			    aiter = div.alt_branch.begin();
			} else {
			    div.div_addr = addr;
			    div.div_dir = extra2;
			    while (div.orig_branch.size()) div.orig_branch.pop_front();
			    while (div.alt_branch.size()) div.alt_branch.pop_front();
			    div.count = 1;
			    div.iter_count = atoi(extra4);
			}
			div.div_value = value;
			last_diverge_addr = addr;
			last_diverge_value = value;
		    } else if (!strcmp(type, "ctrl_block_instrument_orig")) {
			if (!is_dup) {
			    inst i;
			    i.addr = addr;
			    i.branch_flag = extra1;
			    div.orig_branch.push_back (i);
			} else {
			    if (is_flipped) {
				if (aiter == div.alt_branch.end()) {
				    fprintf (stderr, "Extra instr on alt path (%s,%s)\n",
					     addr, extra1);
				    diverged = true;
				} else if (aiter->addr != addr && aiter->branch_flag != extra1) {
				    fprintf (stderr, "Alternate path from %s diverges (%s,%s) vs (%s,%s)\n",
					     div.div_addr.c_str(),
					     aiter->addr.c_str(), aiter->branch_flag.c_str(), addr, extra1);
				} else {
				    aiter++;
				}
			    } else {
				if (oiter == div.orig_branch.end()) {
				    fprintf (stderr, "Extra instr on orig path (%s,%s)\n",
					     addr, extra1);
				} else if (oiter->addr != addr && oiter->branch_flag != extra1) {
				    fprintf (stderr, "Original path from %s diverges (%s,%s) vs (%s,%s)\n",
					     div.div_addr.c_str(),
					     oiter->addr.c_str(), oiter->branch_flag.c_str(), addr, extra1);
				} else {
				    oiter++;
				}
			    }
			}
		    } else if (!strcmp(type, "ctrl_block_instrument_alt")) {
			if (!is_dup || diverged) {
			    inst i;
			    i.addr = addr;
			    i.branch_flag = extra1;
			    div.alt_branch.push_back (i);
			} else {
			    if (!is_flipped) {
				if (aiter == div.alt_branch.end()) {
				    fprintf (stderr, "Extra instr on alt path from %s (%s,%s)\n",
					     div.div_addr.c_str(), addr, extra1);
				    diverged = true;
				} else if (aiter->addr != addr && aiter->branch_flag != extra1) {
				    fprintf (stderr, "Alternate path from %s diverges (%s,%s) vs (%s,%s)\n",
					     div.div_addr.c_str(),
					     aiter->addr.c_str(), aiter->branch_flag.c_str(), addr, extra1);
				} else {
				    aiter++;
				}
			    } else {
				if (oiter == div.orig_branch.end()) {
				    fprintf (stderr, "Extra instr on orig path (%s,%s)\n",
					     addr, extra1);
				} else if (oiter->addr != addr && oiter->branch_flag != extra1) {
				    fprintf (stderr, "Original path from %s diverges (%s,%s) vs (%s,%s)\n",
					     div.div_addr.c_str(),
					     oiter->addr.c_str(), oiter->branch_flag.c_str(), addr, extra1);
				} else {
				    oiter++;
				}
			    }
			}
		    } else if (!strcmp(type, "ctrl_merge")) {
			if (diverged) {
			    div.merge_value = value;
			    divergence_exceptions[make_pair(div.div_addr,value)] = div;
			} else if (is_dup) {
			    if (strcmp(addr, div.merge_addr.c_str())) {
				fprintf (stderr, "ERROR: merge address different (%s vs. %s) for div %s\n",
					 addr, div.merge_addr.c_str(), div.div_addr.c_str());
			    }
			    div.div_value = div.merge_value = "-1,-1,-1";
			    divergences[div.div_addr] = div;
			} else {
			    div.merge_addr = addr;
			    div.merge_value = value;
			    divergences[div.div_addr] = div;
			}
		    } else if (!strcmp(type, "rangev") || !strcmp(type, "rangev_write")) {
			auto iter = indexes.find(addr);
			if (iter == indexes.end()) {
			    struct index_div rw;
			    rw.addr = addr;
			    rw.type = type;
			    rw.value = value;
			    indexes[addr] = rw;
			} else {
			    if (type != iter->second.type) {
				fprintf (stderr, "Differnet types for address %s: %s, %s\n", 
					 addr, type, iter->second.type.c_str());
				return -1;
			    }
			    int v1 = atoi(value);
			    int v2 = atoi(iter->second.value.c_str());
			    if (v1 > v2) iter->second.value = value;
			}
		    } else if (!strcmp(type, "syscall_read_extra")) {
			// Same format as index so reuse
			auto iter = indexes.find(addr);
			if (iter == indexes.end()) {
			    struct index_div sys;
			    sys.addr = addr;
			    sys.type = type;
			    sys.value = value;
			    indexes[addr] = sys;
			} else {
			    if (type != iter->second.type) {
				fprintf (stderr, "Differnet types for syscall %s: %s, %s\n", 
					 addr, type, iter->second.type.c_str());
				return -1;
			    }
			    int v1 = atoi(value);
			    int v2 = atoi(iter->second.value.c_str());
			    if (v1 > v2) iter->second.value = value;
			}
		    }
		} else {
		    fprintf (stderr, "check %s: invalid format\n", line);
		    return -1;
		}
	    }
	}
	fclose (file);
    }

    for (iter = divergences.begin(); iter != divergences.end(); ++iter) {
	print_divergence (iter->second);
    }

    for (auto diter = divergence_exceptions.begin(); diter != divergence_exceptions.end(); ++diter) {
	print_divergence (diter->second);
    }

    for (auto iter = indexes.begin(); iter != indexes.end(); ++iter) {
	print_index_rw (iter->second);
    }

    return 0;
}
