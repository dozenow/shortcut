#include <iostream>
#include <stdlib.h>
#include <vector>

//A Node represents an instruction, such as "mov EAX, 20" by its line number in the assembly exslice1.c file
//A Node has a vector of input Edges and a vector of output Edges
//The bool extra flag is for the 'mark and sweep' tracing garbage collection to remove unnecessary slice instructions. If the node is marked as extra, then it is extraneous and unnecessary, so we can remove the instruction from the slice.
struct Node {
	int lineNum;
	std::vector<Edge*> inEdges;
	std::vector<Edge*> outEdges;
	bool extra = false;
}

//An Edge represents the relationship between two Nodes in our graph. Each edge has a pointer to its origin Node and a pointer to its destination Node.
//We have a boolean taint flag to keep track of the tainted inputs into our instructions.
struct Edge {
	Node* start;
	Node* finish;
	bool taint = true;
}

//The directed acyclic Graph of instructions is represented by a vector of Nodes.
struct instrGraph {
	std::vector<Node*> nodes;
}

//change to use same taint format as pin
struct tregister {
	std::vector<Node*>;

	//for example EAX
	setWhole();
	//for example AX
	setLastTwoBytes();
	//for example AH
	setHigherByte();
	//for example AL
	setLowerByte();
}

struct registers {
	std::vector<tregister*>
}

//The memory state of our slice is represented by a map of 32-bit addresses and the Nodes that most recently affected the memory location at that address.
struct memLocations {
	std::map<ulong, Node*> mapMem;
}

//The 32-bit EFLAGS register is represented as a vector of nodes that most recently affected each byte of the EFLAGS register.
//We have an explicit way to modify certain flag bits such as the "CF, Carry Flag" that is the first 0 bit of the EFLAGS register.  
struct eflags {
	std::vector<Node*>;

	//set parts of the 4 byte EFLAGS register
	setCF();
	setPF();
	setAF();
	setZF();
	setSF();
	setTF();
	setIF();
	setDF();
	setOF();
}
