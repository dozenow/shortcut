#include <iostream>
#include <stdlib.h>
#include <vector>

//add comments explain each struct, class
//add flag that marks whether should be cleaned or not. flag and sweep garbage collection
// two sets of edges (input edges and output edges)
struct Node {
	int lineNum;
	std::vector<Edge*> inEdges;
	std::vector<Edge*> outEdges;
	bool dirty = false;
}

struct Edge {
	Node* start;
	Node* finish;
}

struct instrGraph {
	std::vector<Node*> nodes;
	std::vector<Edge*> edges;
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

struct memLoc {
	ulong address;
	std::vector<Node*>;
}

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
