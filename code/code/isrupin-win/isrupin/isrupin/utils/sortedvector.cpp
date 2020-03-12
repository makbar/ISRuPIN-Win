#include <vector>

#include "sortedvector.h"

using namespace std;

template <class Entry>
SortedVector<Entry>::SortedVector()
{
	entries = new vector<SortedVectorEntry>();
}


template <class Entry>
void SortedVector<Entry>::Insert(unsigned long low, unsigned long high,
		Entry &entry)
{
}
