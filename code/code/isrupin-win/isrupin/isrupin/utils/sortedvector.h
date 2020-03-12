#ifndef SORTEDVECTOR_HH
#define SORTEDVECTOR_HH




template <class Entry>
class SortedVector {
public:
	SortedVector();
	void Insert(unsigned long low, unsigned long high, Entry &entry);

protected:
	class SortedVectorEntry {
	public:
		unsigned long low, high;
		Entry entry;
	};

	std::vector<SortedVectorEntry> *entries;
};

#endif
