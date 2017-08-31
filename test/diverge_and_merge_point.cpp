#include <iostream>
#include <string>
#include <fstream>
#include <list>
#include <vector>
#include <assert.h>
#include <string.h>

using namespace std;

struct block { 
    u_long clock;
    uint64_t index;
    uint32_t bb_addr;
};

struct result {
    int direction;
    struct block block1;
    struct block block2;
};

#define CHECK_BLOCK_INDEX(block1,block2) (block1.clock==block2.clock && block1.index == block2.index)

vector<struct result> result_block;
#define INSERT_FIRST 1
#define INSERT_SECOND 2
#define SUBSTITUTE 3

#define DEBUG 0
#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))
#define LEFT_COST 1
#define DOWN_COST 1
#define DIAG_COST 2
#define MAX_DISTANCE 99999999

static inline void set_result (struct block block1, struct block block2, int direction)
{
    struct result result;
    memcpy (&result.block1, &block1, sizeof(struct block));
    memcpy (&result.block2, &block2, sizeof(struct block));
    result.direction = direction;
    result_block.push_back (result);
}

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
                //if (DEBUG) printf ("pos %d %u\n", x-1, block_list1[x-1].bb_addr);
        }
        for (y = 1; y < length2 + 1; ++y) {
                //printf ("y is %d\n", y);
                matrix[0][y] = matrix[0][y-1] + 1;
                //if (DEBUG) printf ("pos %d %u\n", y-1, block_list2[y-1].bb_addr);
        }
        for (x = 1; x < length1 + 1; ++x) {
                for (y =1; y < length2 + 1; ++y) {
                        if (block_list1[x-1].bb_addr == block_list2[y-1].bb_addr) 
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
                    if (DEBUG) 
                        cout << "insert at first with" << " block " << std::hex << block_list2[y-1].bb_addr << std::dec
                            << "clock (" << block_list2[y-1].clock << ")" 
                            << "index (" << block_list2[y-1].index << ")" << endl;
                    //block_list1[0]? is this right?
                    set_result (block_list1[0], block_list2[y-1], INSERT_FIRST);
                    --y;
                    continue;
                }
                if (y == 0) {
                    if (DEBUG) 
                        cout << "insert at second with" << " block " << std::hex << block_list1[x-1].bb_addr << std::dec
                            << " clock (" << block_list1[x-1].clock << ")" 
                            << " index (" << block_list1[x-1].index << ")" << endl;
                    set_result (block_list1[x-1], block_list2[0], INSERT_SECOND);
                    --x;
                    continue;
                }
        
                min = MIN3 (matrix[x-1][y-1], matrix[x-1][y], matrix[x][y-1]);
                if (matrix[x-1][y-1] == min) {
                        if (matrix[x-1][y-1] != matrix[x][y]) {
                                printf ("substitute @%llu, %llu, block_addr %x, %x\n", block_list1[x-1].index, block_list2[y-1].index, block_list1[x-1].bb_addr, block_list2[y-1].bb_addr);
                                set_result (block_list1[x-1], block_list2[y-1], SUBSTITUTE);
                        }
                        --x;
                        --y;
                } else if (matrix[x-1][y] == min) {
                    if (DEBUG) 
                        cout << "insert at second with" << " block " << std::hex << block_list1[x-1].bb_addr << std::dec
                            << " clock (" << block_list1[x-1].clock << ")"
                            << " index (" << block_list1[x-1].index << ")" << endl;
                    set_result (block_list1[x-1], block_list2[y], INSERT_SECOND);
                    --x;
                } else {
                    if (DEBUG) 
                        cout << "insert at first with" << " block " << std::hex << block_list2[y-1].bb_addr << std::dec
                            << " clock (" << block_list2[y-1].clock << ")"
                            << " index (" << block_list2[y-1].index << ")" << endl;
                    set_result (block_list1[x], block_list2[y-1], INSERT_FIRST);
                    --y;
                }
        }

        result = matrix[length1][length2];
        for (i=0; i<length1+1; ++i) 
                free (matrix[i]);
        free (matrix);
        return result/2;

}

void get_bbinfo_content (ifstream &in, vector<block> &block_list) { 
    string line;
    uint32_t addr;
    u_long clock;
    uint64_t index;

    while (getline (in, line)) {
       if (line.compare (0, 4, "[BB]") == 0) { 
           sscanf (line.c_str(), "[BB]%x, #%llu,%lu ", &addr, &index, &clock);
           struct block bb;
           bb.clock = clock;
           bb.bb_addr = addr;
           bb.index = index;
           block_list.push_back (bb);
       }
    }
}

void print_all_blocks (vector<block> &block_list) { 
    int count = 0;
    for (auto i = block_list.begin(); i != block_list.end(); ++i) { 
        if (DEBUG) cout<< i->bb_addr << ": block index "<< i->index << " clock " << i->clock <<endl;
        ++count;
    }
}

int main (int argc, char* argv[]) { 
    string output_filename = "/tmp/ctrl_flow_instrument";
    if (argc != 3) {
        cerr << "usage: find_diverge_and_merge bb_info_file1 bb_info_file2" <<endl;
    }
    ifstream bbinfo1_in (argv[1], ios::in);
    ifstream bbinfo2_in (argv[2], ios::in);
    ofstream output (output_filename, ofstream::out | ofstream::trunc);
    if (!bbinfo1_in.is_open() || !bbinfo2_in.is_open()) {
        cerr << "cannot open input files" <<endl;
    }
    if (!output.is_open()) { 
        cerr << "cannot open output file" <<endl;
    }
    vector<block> bbinfo_block1;
    vector<block> bbinfo_block2;

    get_bbinfo_content (bbinfo1_in,bbinfo_block1);
    get_bbinfo_content (bbinfo2_in,bbinfo_block2);

    print_all_blocks (bbinfo_block1);
    print_all_blocks (bbinfo_block2);

    if (DEBUG) cout << "=======" << endl;
    distance (bbinfo_block1, bbinfo_block2, bbinfo_block1.size(), bbinfo_block2.size());
    cout << "=======" << endl;
    int last_direction = -1;
    for (auto iter = result_block.begin(); iter != result_block.end(); ++iter) { 
        if (last_direction == -1) last_direction = iter->direction;
        if (iter->direction == SUBSTITUTE) { 
            cerr << "[TODO] Haven't tested substitution of blocks." <<endl;
        }
    }
    int retval = (last_direction == INSERT_FIRST?2:1);

    //figure out the merge point
    u_long diverge_clock = 0;
    uint64_t diverge_index = 0;
    struct block last_diverge1;
    struct block last_diverge2;
    memset (&last_diverge1, 0, sizeof(struct block));
    memset (&last_diverge2, 0, sizeof(struct block));
    
    for (int i = result_block.size() - 1; i >= 0; --i) { 
        if (DEBUG) printf ("result %lu,%llu @FIRST, %lu, %llu @SECOND.\n", result_block[i].block1.clock, result_block[i].block1.index, result_block[i].block2.clock, result_block[i].block2.index);
        if (!CHECK_BLOCK_INDEX(result_block[i].block1, last_diverge1) || !CHECK_BLOCK_INDEX(result_block[i].block2, last_diverge2)) {
            if (last_diverge1.clock != 0 || last_diverge2.clock != 0) {
                printf ("Merged right before %lu,%llu @FIRST, %lu, %llu @SECOND.\n", last_diverge1.clock, last_diverge1.index, last_diverge2.clock, last_diverge2.index);
            }
            printf ("Diverge before %lu,%llu @FIRST, %lu, %llu @SECOND.\n", result_block[i].block1.clock, result_block[i].block1.index, result_block[i].block2.clock, result_block[i].block2.index);
            memcpy (&last_diverge1, &result_block[i].block1, sizeof(struct block));
            memcpy (&last_diverge2, &result_block[i].block2, sizeof(struct block));
        }
        if (result_block[i].direction != INSERT_FIRST) last_diverge1.index ++;
        if (result_block[i].direction != INSERT_SECOND) last_diverge2.index ++;
        //output << "[CTRL_INFO] " << result_blockresult_block[i].index << ":" << result_block[i].clock << std::hex << ", 0x" << result_block[i].bb_addr << std::dec << endl;
    }
    if (last_diverge1.clock != 0 || last_diverge2.clock != 0) { 
        printf ("Merged right before %lu,%llu @FIRST, %lu, %llu @SECOND.\n", last_diverge1.clock, last_diverge1.index, last_diverge2.clock, last_diverge2.index);
    }

    cout << "=======" << endl;
    cout << "results are written to " << output_filename << endl;
    output.close();
    return retval;
}
