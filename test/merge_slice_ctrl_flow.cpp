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

vector<int> result_start_line;
vector<int> result_end_line;
vector<int> result_direction;
vector<long> result_block_index;
vector<uint32_t> result_addr;
#define INSERT_FIRST 1
#define INSERT_SECOND 2
#define SUBSTITUTE 3

#define DEBUG 0
#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))
#define LEFT_COST 1
#define DOWN_COST 1
#define DIAG_COST 2
#define MAX_DISTANCE 99999999

static inline long get_block_index (string line, uint32_t &addr) { 
   size_t info_pos = line.find ("[BLOCK_INFO]"); 
   if (info_pos == string::npos) { 
       if (line.find ("[SLICE_VERIFICATION]") == string::npos && line.find("[SLICE_EXTRA]") == string::npos) {
           cerr << "line doesn't have a BLOCK_INFO:" << line <<endl;
       }
       return -1;
   } else { 
       size_t stop = line.find ("*", info_pos);
       string index_str = line.substr (info_pos + 13, stop - info_pos - 13);
       long index;
       sscanf (index_str.c_str(), "%lu,%x", &index, &addr);
       return index;
   }
}

static inline long get_block_index (string line) { 
    uint32_t addr = 0;
    return get_block_index (line, addr);
}

static inline void set_result (int start_line, int end_line, int direction, long block_index, uint32_t addr)
{
    result_start_line.push_back (start_line);
    result_end_line.push_back (end_line);
    result_direction.push_back (direction);
    result_block_index.push_back (block_index);
    result_addr.push_back (addr);
}

int distance (vector<block> &block_list1, vector<block> &block_list2, int length1, int length2, vector<string> &slice_content1, vector<string> slice_content2) {
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
                //if (DEBUG) printf ("pos %d %u\n", x-1, block_list1[x-1].hash);
        }
        for (y = 1; y < length2 + 1; ++y) {
                //printf ("y is %d\n", y);
                matrix[0][y] = matrix[0][y-1] + 1;
                //if (DEBUG) printf ("pos %d %u\n", y-1, block_list2[y-1].hash);
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
                    uint32_t addr = 0;
                    long index = get_block_index (slice_content2[block_list2[y-1].start_line - 1], addr);
                    cout << "insert at first @ " << y-1 << ", block_list " << block_list2[y-1].hash << endl;
                    cout << "Line start (" << block_list2[y-1].start_line << "): " << slice_content2[block_list2[y-1].start_line - 1] << endl;
                    cout << "Line end(" << block_list2[y-1].end_line << "):" <<  slice_content2[block_list2[y-1].end_line - 1] << endl;
                    //here the actual start address for this block should always be in the next line
                    cout << "Block index " << index << " addr: " << std::hex << addr << std::dec << endl;
                    set_result (block_list2[y-1].start_line, block_list2[y-1].end_line, INSERT_FIRST, index, addr);
                    --y;
                    continue;
                }
                if (y == 0) {
                    uint32_t addr = 0;
                    //here the actual start address for this block should always be in the next line
                    long index = get_block_index (slice_content1[block_list1[x-1].start_line - 1], addr);

                    cout << "insert at second @ " << x-1 << ", block_list " << block_list1[x-1].hash << endl;
                    cout << "Line start (" << block_list1[x-1].start_line << "): " << slice_content1[block_list1[x-1].start_line - 1] << endl;
                    cout << "Line end(" << block_list1[x-1].end_line << "):" <<  slice_content1[block_list1[x-1].end_line - 1] << endl;
                    cout << "Block index " << index << " addr: " << std::hex << addr << std::dec << endl;
                    set_result (block_list1[x-1].start_line, block_list1[x-1].end_line, INSERT_SECOND, index, addr);
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
                    uint32_t addr = 0;
                    //here the actual start address for this block should always be in the next line
                    long index = get_block_index (slice_content1[block_list1[x-1].start_line - 1], addr);

                    cout << "insert at second @ " << x-1 << ", block_list " << block_list1[x-1].hash << endl;
                    cout << "Line start (" << block_list1[x-1].start_line << "): " << slice_content1[block_list1[x-1].start_line - 1] << endl;
                    cout << "Line end(" << block_list1[x-1].end_line << "):" <<  slice_content1[block_list1[x-1].end_line - 1] << endl;
                    cout << "Block index " << index << " addr: " << std::hex << addr << std::dec << endl;
                    set_result (block_list1[x-1].start_line, block_list1[x-1].end_line, INSERT_SECOND, index, addr);
                    --x;
                } else {
                    uint32_t addr = 0;
                    long index = get_block_index (slice_content2[block_list2[y-1].start_line - 1], addr);
                    cout << "insert at first @ " << y-1 << ", block_list " << block_list2[y-1].hash << endl;
                    cout << "Line start (" << block_list2[y-1].start_line << "): " << slice_content2[block_list2[y-1].start_line - 1] << endl;
                    cout << "Line end(" << block_list2[y-1].end_line << "):" <<  slice_content2[block_list2[y-1].end_line - 1] << endl;
                    //here the actual start address for this block should always be in the next line
                    cout << "Block index " << index << " addr: " << std::hex << addr << std::dec << endl;
                    set_result (block_list2[y-1].start_line, block_list2[y-1].end_line, INSERT_FIRST, index, addr);
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
    //cout << "block List (" << block.start_line << "," <<block.end_line << ": " << block.hash << ", content: "<< block_content << endl;
}

static inline string get_inst (string line) { 
    if (line.find ("[ORIGINAL_SLICE]") != string::npos) {
        //for SLICE, we only use the ip
        size_t index = line.find("[ORIGINAL_SLICE]");
        size_t space_index = line.find (" ", index + 17);
        return line.substr (index, space_index - index);

    } else {
        //for SLICE_EXTRA/VERIFICATION.., we use the actual disasm
        size_t index = line.find ("/");
        if (index == string::npos) { 
            cerr << "unrecognized line: " << line <<endl;
            assert (0);
        }
        if (line.find ("[SLICE_VERIFICATION_DEBUG]") != string::npos)
            return "";
        return line.substr (0, index);
    }
}

void get_slice_content (ifstream &in, vector<string> &slice_content, vector<block> &block_list) { 
    string line;
    bool start = false;
    int block_start = 0;
    int block_end = 0;
    int count = 0;
    string block_content = "";
    long last_block_index = -1;
    while (getline (in, line)) {
        ++ count;
        slice_content.push_back (line);
        if (line == "/*slice begins*/") {
            start = true;
            block_start = count + 1;
        }
        if (start) { 
            if (line == "/* restoring address and registers */") {
                add_to_block_list (block_list, block_start, count - 1, block_content);
                break;
            }
            if (line[0] == '/' && line[1] == '*')
                continue;
            long block_index = get_block_index (line);
            if (block_index == -1) { 
                //TODO: I know some lines like SLICE_EXTRA and SLICE_VERIFICATION don't have this index
                block_index = last_block_index;
            }
            //if (line.find ("jump_diverge") != string::npos /*|| line.find ("call ") != string::npos*/) { 
            if (block_index != last_block_index) { 
                last_block_index = block_index;
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
        if (DEBUG) cout<< count << ": block from "<< i->start_line << " to " << i->end_line << " hash: "<< i->hash <<endl;
        ++count;
    }
}

int main (int argc, char* argv[]) { 
    string output_filename = "/tmp/ctrl_flow_instrument";
    if (argc != 3) {
        cerr << "usage: merge_slice_ctrl_flow SLICE1 SLICE2" <<endl;
    }
    ifstream slice1_in (argv[1], ios::in);
    ifstream slice2_in (argv[2], ios::in);
    ofstream output (output_filename, ofstream::out | ofstream::trunc);
    if (!slice1_in.is_open() || !slice2_in.is_open()) {
        cerr << "cannot open input files" <<endl;
    }
    if (!output.is_open()) { 
        cerr << "cannot open output file" <<endl;
    }
    vector<string> slice_content1;
    vector<string> slice_content2;
    vector<block> slice_block1;
    vector<block> slice_block2;

    get_slice_content (slice1_in, slice_content1, slice_block1);
    get_slice_content (slice2_in, slice_content2, slice_block2);

    print_all_blocks (slice_block1);
    print_all_blocks (slice_block2);

    cout << "=======" <<endl;
    distance (slice_block1, slice_block2, slice_block1.size(), slice_block2.size(), slice_content1, slice_content2);
    cout << "=======" << endl;
    int last_direction = -1;
    for (auto iter = result_direction.begin(); iter != result_direction.end(); ++iter) { 
        if (last_direction == -1) last_direction = *iter;
        if (*iter == SUBSTITUTE) { 
            cerr << "Cannot handle substitution of blocks." <<endl;
            exit(-1);
        }
        if (last_direction != *iter) {
            cerr << "Cannot handle the case where each execution has some extra blocks." << endl;
            exit (-1);
        }
    }
    cout << "results are written to " << output_filename << endl;
    //cout << result_start_line << "," << result_end_line << "," << result_direction << "," << result_block_index << "," << std::hex << result_addr << std::dec << endl;
    int result = (last_direction == INSERT_FIRST?2:1);
    for (int i = result_direction.size() - 1; i >= 0; --i) { 
        output << "[CTRL_INFO] " << result_block_index[i] << "," << std::hex << "0x" << result_addr[i] << std::dec << endl;
    }
    output.close();
    return result;
}
