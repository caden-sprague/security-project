#ifndef _ADJLIST_H_
#define _ADJLIST_H_
#include <iostream>

using namespace std;

struct Node {
   int nodeID;
   Node *next;
};

class AdjList{
public:
   AdjList() { head = nullptr; }   // Constructor
   ~AdjList();                     // Destructor
   void AddNode(int x);            // Append a node to the end of the list
   Node* GetHeadNode();            // Return the head node pointer
   
private:
   Node* head;
};

// Destructor
AdjList::~AdjList() {
   while (head != nullptr){
      Node* p = head;
      head = head->next;
      delete p;
   }
}

// Append a node to the end of the list
void AdjList::AddNode(int id) {
   Node* p = new Node;
   p->nodeID = id;
   
   if (head == nullptr){
      head = p;
      p->next = nullptr;
      return;
   }
   
   Node* q = head;
   while (q->next != nullptr){
      q = q->next;
   }

   q->next = p;
   p->next = nullptr;
}


// Return the head node pointer
Node* AdjList::GetHeadNode() {
   return head;
}

#endif
