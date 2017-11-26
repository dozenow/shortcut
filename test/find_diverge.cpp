#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>

#include <iostream>
#include <string>
#include <vector>
using namespace std;

//#define DPRINT printf
#define DPRINT(x,...)

struct linedata {
    string address;
    string pid;
    string clock;
    string blockno;
    string branch_flag;
    u_long weight;
};

static int parse_line (string s, struct linedata& data)
{
    u_int pos = s.find(",");
    if (pos == string::npos) return -1;
    data.address = s.substr(0,pos);
    s = s.substr(pos);
    pos = s.find("#");
    if (pos == string::npos) return -1;
    s = s.substr(pos+1);
    pos = s.find(",");
    if (pos == string::npos) return -1;
    data.blockno = s.substr(0,pos);
    s = s.substr(pos+1);
    pos = s.find(" ");
    if (pos == string::npos) return -1;
    data.clock = s.substr(0,pos);
    s = s.substr(pos+10);
    pos = s.find(" ");
    if (pos == string::npos) return -1;
    data.pid = s.substr(0,pos);
    s = s.substr(pos+1);
    data.branch_flag = s.substr(0, 1);
    data.weight = 1;

    return 0;
}

int read_file (char* filename, vector<struct linedata>& ins)
{
    FILE* file1 = fopen (filename, "r");
    if (file1 == NULL) {
	fprintf (stderr, "Cannot open %s, errno=%d\n", filename, errno);
	return -1;
    }

    while (!feof(file1)) {
	char line[256];
	if (fgets (line, 256, file1)) {
	    if (!strncmp (line, "[INST]", 6)) {
		struct linedata data;
		if (parse_line (line+6, data) == 0) {
		    ins.push_back (data);
		} else {
		    fprintf (stderr, "Unable to parse line %s\n", line);
		}
	    } else if (!strncmp (line, "[SUB]", 5)) {
		u_long sweight;
		assert (sscanf (line, "[SUB] %ld instructions", &sweight) == 1);
		ins.back().weight += sweight;
	    }
	}
    }	

    fclose (file1);
    return 0;
}

int main (int argc, char* argv[])
{
    vector<struct linedata> bb1, bb2;

    if (argc != 3) {
	fprintf (stderr, "Format: find_diverge [bb_file1] [bb_file2]\n");
    }

    if (read_file (argv[1], bb1) < 0) return -1;
    if (read_file (argv[2], bb2) < 0) return -1;

    int size1 = bb1.size();
    int size2 = bb2.size();

    int line1 = 0;
    int line2 = 0;
    while (line1 != size1 && line2 != size2) {
	if (bb1[line1].address == bb2[line2].address) {
	    DPRINT ("Match: %s\n", bb1[line1].address.c_str());
	    line1++;
	    line2++;
	} else {
	    if (line1 == 0) {
		printf ("Diverge before first block\n");
	    } else {
		printf ("%s ctrl_diverge %s,%s,%d orig_branch %s iter 1\n", bb1[line1-1].address.c_str(), bb1[line1-1].pid.c_str(),
			bb1[line1-1].clock.c_str(), atoi(bb1[line1-1].blockno.c_str())+1, bb1[line1-1].branch_flag.c_str());
	    }
	    DPRINT ("Mismatch: %s %s\n", bb1[line1].address.c_str(), bb2[line2].address.c_str());
	    int best1 = INT_MAX/2;
	    int best2 = INT_MAX/2;
	    int bestline1 = bb1.size();
	    int bestline2 = bb2.size();
	    long weight1 = 0;
	    for (int mline1 = line1-1; mline1 < size1; mline1++) {
		DPRINT ("Try %d:%s\n", mline1, bb1[mline1].address.c_str());

		weight1 += (bb1[mline1].branch_flag != "-");
		if (bb1[mline1].weight > 1) weight1 += bb1[mline1].weight;

		long weight2 = 0;
		int startat = (mline1 == line1-1) ? line2 : line2-1;
		for (int mline2 = startat; mline2 < size2; mline2++) {

		    weight2 += (bb2[mline2].branch_flag != "-");
		    if (bb2[mline2].weight > 1) weight2 += bb2[mline2].weight;

		    if (bb1[mline1].address == bb2[mline2].address) {
			DPRINT ("Match found for %d:%s at %d:%s\n", mline1, bb1[mline1].address.c_str(), 
				mline2, bb2[mline2].address.c_str());
			if (weight1+weight2 < best1+best2) {
			    DPRINT ("Best so far\n");
			    best1=weight1;
			    best2=weight2;
			    bestline1 = mline1;
			    bestline2 = mline2;
			}
			break;
		    }
		    if (best1+best2 <= weight1) break;
		}
		DPRINT ("best1 %d best2 %d\n", best1, best2);
		if (best1+best2 <= weight1) break;
	    }
	    
	    for (int i = line1; i < bestline1; i++) {
		printf ("%s ctrl_block_instrument_orig branch %s\n", bb1[i].address.c_str(), bb1[i].branch_flag.c_str());
	    }
	    for (int i = line2; i < bestline2; i++) {
		printf ("%s ctrl_block_instrument_alt branch %s\n", bb2[i].address.c_str(), bb2[i].branch_flag.c_str());
	    }

	    printf ("%s ctrl_merge %s,%s,%s\n", bb1[bestline1].address.c_str(), bb1[bestline1].pid.c_str(),
		    bb1[bestline1].clock.c_str(), bb1[bestline1].blockno.c_str());
	    line1 = bestline1;
	    line2 = bestline2;
	}
    }
    
    return 0;
}
