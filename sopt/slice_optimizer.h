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

struct memValue {
	std:vector<Node*>;
}

