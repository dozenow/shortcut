#include <iostream>
#include <string>
#include <fstream>
#include <list>
#include <vector>
#include <assert.h>

using namespace std;

struct block { 
    int start_line;
    int end_line;
    size_t hash;
};

#define DEBUG 1
#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))
#define LEFT_COST 1
#define DOWN_COST 1
#define DIAG_COST 2
#define MAX_DISTANCE 99999999

int distance (vector<block> &block_list1, vector<block> &block_list2, int length1, int length2) {
        //int* matrix[length1+1];
        int** matrix = NULL;
        int i = 0;
        int x = 0, y = 0;
        int result = 0;
        
        matrix = (int**)malloc (sizeof (int*) * (length1+1));
        for (; i<length1+1; ++i) {
                matrix[i] = (int*)malloc (sizeof (int)* (length2+1));
                assert (matrix[i] != NULL);
        }
        matrix[0][0] = 0;
        matrix[1][0] = 0;
        //printf ("%d, %d length\n", length1, length2);
        for (x = 1; x < length1 + 1; ++x) {
                matrix[x][0] = matrix[x-1][0] + 1;      
                if (DEBUG) printf ("pos %d %u\n", x-1, block_list1[x-1].hash);
        }
        for (y = 1; y < length2 + 1; ++y) {
                //printf ("y is %d\n", y);
                matrix[0][y] = matrix[0][y-1] + 1;
                if (DEBUG) printf ("pos %d %u\n", y-1, block_list2[y-1].hash);
        }
        printf ("init done.\n");
        for (x = 1; x < length1 + 1; ++x) {
                for (y =1; y < length2 + 1; ++y) {
                        if (block_list1[x-1].hash == block_list2[y-1].hash) 
                                matrix[x][y] = matrix[x-1][y-1];
                        else {
                                matrix[x][y] = MIN3 (matrix[x-1][y] + LEFT_COST, matrix[x][y-1] + DOWN_COST, matrix[x-1][y-1] + DIAG_COST);
                        }
                }
        }
        //backtrace the path
        x = length1;
        y = length2;
        while (x != 0 || y != 0) {
                int min = MAX_DISTANCE;
                if (x == 0) {
                        if (DEBUG) printf ("insert at first @ %d, block_list %u\n", y-1, block_list2[y-1].hash);
                        --y;
                        continue;
                }
                if (y == 0) {
                        //insert at the first array
                        if (DEBUG) printf ("insert at second @ %d, block_list %u\n", x-1, block_list1[x-1].hash);
                        --x;
                        continue;
                }
        
                min = MIN3 (matrix[x-1][y-1], matrix[x-1][y], matrix[x][y-1]);
                if (matrix[x-1][y-1] == min) {
                        if (matrix[x-1][y-1] != matrix[x][y]) {
                                if (DEBUG) printf ("substitute @%d, %d, block_list %u, %u\n", x-1, y-1, block_list1[x-1].hash, block_list2[y-1].hash);
                        }
                        --x;
                        --y;
                } else if (matrix[x-1][y] == min) {
                        //insert at the first array
                        if (DEBUG) printf ("insert at second @ %d, block_list %u\n", x-1, block_list1[x-1].hash);
                        --x;
                } else {
                        //insert at the second arry
                        if (DEBUG) printf ("insert at first @ %d, block_list %u\n", y-1, block_list2[y-1].hash);
                        --y;
                }
        }

        result = matrix[length1][length2];
        for (i=0; i<length1+1; ++i) 
                free (matrix[i]);
        free (matrix);
        return result/2;

}

static void inline add_to_block_list (vector<block> &block_list, int start, int end, string block_content) { 
    struct block block;
    block.start_line = start;
    block.end_line = end;
    struct hash<string> h;
    block.hash = h(block_content);
    block_list.push_back (block);
}

static inline string get_inst (string line) { 
    size_t index = line.find ("/");
    if (index == string::npos) { 
        cerr << "unrecognized line: " << line <<endl;
        assert (0);
    }
    return line.substr (0, index);
}

void get_slice_content (ifstream &in, list<string> &slice_content, vector<block> &block_list) { 
    string line;
    bool start = false;
    int block_start = 0;
    int block_end = 0;
    int count = 0;
    string block_content = "";
    while (getline (in, line)) {
        ++ count;
        if (line == "/*slice begins*/") {
            start = true;
            block_start = count + 1;
        }
        if (start) { 
            if (line == "/* restoring address and registers */") {
                add_to_block_list (block_list, block_start, count - 1, block_content);
                break;
            }
            slice_content.push_back (line);
            if (line[0] == '/' && line[1] == '*')
                continue;
            if (line.find ("jump_diverge") != string::npos) { 
                add_to_block_list (block_list, block_start, count - 1, block_content);
                block_start = count;
                block_content = "";
            }
            block_content += get_inst (line);
        }
    }
}

void print_all_blocks (vector<block> &block_list) { 
    int count = 0;
    for (auto i = block_list.begin(); i != block_list.end(); ++i) { 
        cout<< count << ": block from "<< i->start_line << " to " << i->end_line << " hash: "<< i->hash <<endl;
        ++count;
    }
}

int main (int argc, char* argv[]) { 
    if (argc != 3) {
        cerr << "usage: merge_slice_ctrl_flow SLICE1 SLICE2" <<endl;
    }
    ifstream slice1_in (argv[1], ios::in);
    ifstream slice2_in (argv[2], ios::in);
    if (!slice1_in.is_open() || !slice2_in.is_open()) {
        cerr << "cannot open input files" <<endl;
    }
    list<string> slice_content1;
    list<string> slice_content2;
    vector<block> slice_block1;
    vector<block> slice_block2;

    get_slice_content (slice1_in, slice_content1, slice_block1);
    get_slice_content (slice2_in, slice_content2, slice_block2);

    print_all_blocks (slice_block1);
    print_all_blocks (slice_block2);

    cout << "=======" <<endl;
    distance (slice_block1, slice_block2, slice_block1.size(), slice_block2.size());
}
