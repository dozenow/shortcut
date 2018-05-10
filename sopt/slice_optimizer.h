#include <iostream>
#include <stdlib.h>
#include <vector>

struct Node {
	string name;
	Set<Edge*> Edges;
}

struct Edge {
	Node* start;
	Node* finish;
}

struct instrGraph {
	Set<Node*> nodes;
	Set<Edge*> edges;
}

struct registers {
	std::set<register*>
}

struct register {
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

struct memLoc {
	string name;
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
