#include<iostream>
#include<fstream>
#include<windows.h>
#include<filesystem>
#include<vector>
#include"pe_headers.hpp"
#include"utils.hpp"

using namespace std;
using namespace std::filesystem;

using std::vector;
using std::pair;

class PE_Header {

private:
	fstream file_stream;
	ios_base::openmode open_mode = ios::in | ios::out | ios::binary;
	ios_base::seekdir readmode = ios::beg;

	unsigned int trans_sympol = 0xffffffff;

public:
	class Dos_Header {
	private:
		WORD e_magic;
		DWORD e_lfanew;

	public:
		void set_e_magic(WORD e_magic) {
			this->e_magic = e_magic;
		}

		void set_e_lfanew(DWORD e_lfanew) {
			this->e_lfanew = e_lfanew;
		}

		WORD get_e_magic() {
			return this->e_magic;
		}

		DWORD get_e_lfanew() {
			return this->e_lfanew;
		}

	};

	class File_Header {
	private:
		WORD NumberOfSection;
		WORD SizeOfOptionalHeader;

	public:
		void set_number_of_section(WORD number_of_section) {
			this->NumberOfSection = number_of_section;
		}

		void set_size_of_optional_header(WORD size_of_optional_header) {
			this->SizeOfOptionalHeader = size_of_optional_header;
		}

		WORD get_number_of_section() {
			return this->NumberOfSection;
		}

		WORD get_size_of_optional_header() {
			return this->SizeOfOptionalHeader;
		}

	};

	class Optional_Header {
	private:
		DWORD AddressOfEntryPoint;
		DWORD ImageBase;
		DWORD SectionAlignment;
		DWORD FileAlignment;
		DWORD SizeOfImage;
		DWORD SizeOfHeaders;

	public:
		void set_address_of_entry_point(DWORD address_of_entry_point) {
			this->AddressOfEntryPoint = address_of_entry_point;
		}
		void set_image_base(DWORD image_base) {
			this->ImageBase = image_base;
		}
		void set_section_alignment(DWORD section_alignment) {
			this->SectionAlignment = section_alignment;
		}
		void set_file_alignment(DWORD file_alignment) {
			this->FileAlignment = file_alignment;
		}
		void set_size_of_image(DWORD size_of_image) {
			this->SizeOfImage = size_of_image;
		}
		void set_size_of_headers(DWORD size_of_headers) {
			this->SizeOfHeaders = size_of_headers;
		}


		DWORD get_address_of_entry_point() {
			return this->AddressOfEntryPoint;
		}
		DWORD get_image_base() {
			return this->ImageBase;
		}
		DWORD get_section_alignment() {
			return this->SectionAlignment;
		}
		DWORD get_file_alignment() {
			return this->FileAlignment;
		}
		DWORD get_size_of_image() {
			return this->SizeOfImage;
		}
		DWORD get_size_of_headers() {
			return this->SizeOfHeaders;
		}

	};

	class NT_Header {
		File_Header file_header;
		Optional_Header optional_header;

	};

	class Section_Header {
	private:
		char* ByteName;
		DWORD virtualSize;
		DWORD VirtualAddress;
		DWORD SizeOfRawData;
		DWORD PointerToRawData;

	public:
		void set_byte_name(char* byte_name) {
			this->ByteName = byte_name;
		}

		void set_virtual_size(DWORD virtual_size) {
			this->virtualSize = virtual_size;
		}

		void set_virtual_address(DWORD virtual_address) {
			this->VirtualAddress = virtual_address;
		}

		void set_size_of_raw_data(DWORD size_of_raw_data) {
			this->SizeOfRawData = size_of_raw_data;
		}

		void set_point_to_raw_data(DWORD pointer_to_raw_data) {
			this->PointerToRawData = pointer_to_raw_data;
		}

		string get_byte_name() {
			return this->ByteName;
		}

		DWORD get_virtual_size() {
			return this->virtualSize;
		}

		DWORD get_virtual_address() {
			return this->VirtualAddress;
		}

		DWORD get_size_of_raw_data() {
			return this->SizeOfRawData;
		}

		DWORD get_pointer_to_raw_data() {
			return this->PointerToRawData;
		}

	};


public:
	PE_Header(const char* file_name);
	~PE_Header();

	template <typename T>
	void pe_field_reader(int p_field, T value);
	void pe_field_reader(int p_field, string& value);
	Dos_Header* read_dos_header();
	File_Header* read_file_header();
	Optional_Header* read_optional_header();
	shared_ptr<Section_Header> read_section_header(DWORD base_address_section_header);
	vector<shared_ptr<PE_Header::Section_Header>> generate_section_headers(pair<unsigned int, DWORD> reloc_section_header);

	pair<unsigned int, DWORD> reloc_section_header(Dos_Header* dos_header, File_Header* file_header);

	unique_ptr<char> get_file_buffer_pointer();

	void write_to_imagebuffer(PE_Header::Dos_Header* dos_header,
		PE_Header::File_Header* file_header,
		PE_Header::Optional_Header* option_header,
		vector<shared_ptr<PE_Header::Section_Header>> section_headers
	);

};


PE_Header::PE_Header(const char* file_name) {
	file_stream.open(file_name, open_mode);
}

PE_Header::~PE_Header() {
	file_stream.close();
}

unique_ptr<char> PE_Header::get_file_buffer_pointer() {
	file_stream.seekg(0, file_stream.end);
	size_t size_file = file_stream.tellg();
	unique_ptr<char> file_buff_p(new char[size_file]);

	file_stream.seekp(0, readmode);
	file_stream.read(file_buff_p.get(), size_file);

	return file_buff_p;

}

pair<unsigned int, DWORD> PE_Header::reloc_section_header(PE_Header::Dos_Header* dos_header, PE_Header::File_Header* file_header) {

	WORD number_of_section;
	pair<unsigned int, DWORD> reloc;

	DWORD position_NT_header;
	DWORD position_section_headers;
	DWORD size_of_optional_header;

	position_NT_header = dos_header->get_e_lfanew();
	size_of_optional_header = file_header->get_size_of_optional_header();
	number_of_section = file_header->get_number_of_section();

	position_section_headers = position_NT_header + size_of_signature + size_of_file_header + size_of_optional_header;
	reloc = make_pair(number_of_section, position_section_headers);

	return reloc;
}


template <typename T>
void PE_Header::pe_field_reader(int p_field, T value) {
	file_stream.seekp(p_field, readmode);
	file_stream.read(reinterpret_cast<char*>(value), sizeof(*value));

}


PE_Header::Dos_Header* PE_Header::read_dos_header() {
	WORD e_magic;
	DWORD e_lfanew;

	static Dos_Header dos_header;
	ZeroMemory(&dos_header, sizeof(dos_header));

	pe_field_reader(position_e_magic, &e_magic);
	pe_field_reader(position_e_lfanew, &e_lfanew);

	dos_header.set_e_magic(e_magic & (unsigned short)trans_sympol);
	dos_header.set_e_lfanew(e_lfanew & trans_sympol);

	return &dos_header;
}

PE_Header::File_Header* PE_Header::read_file_header() {
	WORD number_of_section;
	WORD size_of_optional_header;

	static File_Header file_header;
	ZeroMemory(&file_header, sizeof(file_header));

	pe_field_reader(position_number_of_section, &number_of_section);
	pe_field_reader(position_size_of_optional_header, &size_of_optional_header);

	file_header.set_number_of_section(number_of_section & (unsigned short)trans_sympol);
	file_header.set_size_of_optional_header(size_of_optional_header & (unsigned short)trans_sympol);

	return &file_header;
}

PE_Header::Optional_Header* PE_Header::read_optional_header() {

	DWORD address_of_entrypoint;
	ULONGLONG image_base;
	DWORD section_alignment;
	DWORD file_alignment;
	DWORD size_of_image;
	DWORD size_of_headers;

	static Optional_Header optional_header;
	ZeroMemory(&optional_header, sizeof(optional_header));

	pe_field_reader(position_address_of_entry_point, &address_of_entrypoint);
	pe_field_reader(position_image_base, &image_base);
	pe_field_reader(position_section_alignement, &section_alignment);
	pe_field_reader(position_file_alignment, &file_alignment);
	pe_field_reader(position_size_of_image, &size_of_image);
	pe_field_reader(position_size_of_headers, &size_of_headers);


	optional_header.set_address_of_entry_point(address_of_entrypoint & trans_sympol);
	optional_header.set_image_base(image_base & trans_sympol);
	optional_header.set_section_alignment(section_alignment & trans_sympol);
	optional_header.set_file_alignment(file_alignment & trans_sympol);
	optional_header.set_size_of_image(size_of_image & trans_sympol);
	optional_header.set_size_of_headers(size_of_headers & trans_sympol);

	return &optional_header;
}

shared_ptr<PE_Header::Section_Header> PE_Header::read_section_header(DWORD base_address_section_headers) {

	shared_ptr<PE_Header::Section_Header> section_header = make_shared<PE_Header::Section_Header>();

	DWORD position_byte_name = base_address_section_headers + offset_byte_name;
	DWORD position_virtual_size = base_address_section_headers + offset_virtual_size;
	DWORD position_virtual_address = base_address_section_headers + offset_virtual_address;
	DWORD position_size_of_raw_data = base_address_section_headers + offset_size_of_raw_data;
	DWORD position_pointer_to_raw_data = base_address_section_headers + offset_pointer_to_raw_data;

	static char byte_name[8];
	DWORD virtual_size;
	DWORD virtual_address;
	DWORD size_of_raw_data;
	DWORD pointer_to_raw_data;

	pe_field_reader(position_byte_name, &byte_name);
	pe_field_reader(position_virtual_size, &virtual_size);
	pe_field_reader(position_virtual_address, &virtual_address);
	pe_field_reader(position_size_of_raw_data, &size_of_raw_data);
	pe_field_reader(position_pointer_to_raw_data, &pointer_to_raw_data);

	section_header->set_byte_name(byte_name);
	section_header->set_virtual_size(virtual_size & trans_sympol);
	section_header->set_virtual_address(virtual_address & trans_sympol);
	section_header->set_size_of_raw_data(size_of_raw_data & trans_sympol);
	section_header->set_point_to_raw_data(pointer_to_raw_data & trans_sympol);

	return section_header;

}

vector<shared_ptr<PE_Header::Section_Header>> PE_Header::generate_section_headers(pair<unsigned int, DWORD> reloc_section_header) {
	vector<shared_ptr<PE_Header::Section_Header>> section_headers;

	unsigned int num_of_section_headers = reloc_section_header.first;
	DWORD position_section_headers = reloc_section_header.second;

	for (int i = 0; i < num_of_section_headers; i++) {
		shared_ptr<PE_Header::Section_Header> section_header = read_section_header(position_section_headers);
		section_headers.emplace_back(section_header);
		position_section_headers = position_section_headers + offset_section_header;
	}

	return section_headers;

}


void PE_Header::write_to_imagebuffer(
	PE_Header::Dos_Header* dos_header,
	PE_Header::File_Header* file_header,
	PE_Header::Optional_Header* option_header,
	vector<shared_ptr<PE_Header::Section_Header>> section_headers) {

	DWORD position_file = 0x00000000;
	DWORD size_of_image = option_header->get_size_of_image();
	DWORD size_of_headers = option_header->get_size_of_headers();
	DWORD section_alignment = option_header->get_section_alignment();

	unique_ptr<char> file_buffer_p = get_file_buffer_pointer();
	unique_ptr<char> image_buffer_p(new char[size_of_image]);

	char* file_buffer = file_buffer_p.get();
	char* image_buffer = image_buffer_p.get();

	file_stream.seekp(position_file, readmode);
	memset(image_buffer, 0, size_of_image);

	size_t image_size_of_headers = get_section_images_buffer(size_of_headers, section_alignment);
	memmove((void*)image_buffer, file_buffer, size_of_headers);

	for (auto item : section_headers) {
		auto section_header = item.get();

		DWORD virtual_address = section_header->get_virtual_address();
		DWORD pointer_to_raw_data = section_header->get_pointer_to_raw_data();
		DWORD size_of_raw_data = section_header->get_size_of_raw_data();

		memmove((void*)(image_buffer + virtual_address), (file_buffer + pointer_to_raw_data), size_of_raw_data);

	}

}


int main() {

	const char* file_name = "C:\\Users\\chris\\Desktop\\notepad.exe";

	PE_Header pe_header(file_name);
	PE_Header::Dos_Header* dos_header = pe_header.read_dos_header();
	PE_Header::File_Header* file_header = pe_header.read_file_header();
	PE_Header::Optional_Header* option_header = pe_header.read_optional_header();
	pair<unsigned int, DWORD> reloc_section_header = pe_header.reloc_section_header(dos_header, file_header);
	vector<shared_ptr<PE_Header::Section_Header>> section_headers = pe_header.generate_section_headers(reloc_section_header);
	//DWORD* p = pe_header.get_file_buffer_pointer();
	pe_header.write_to_imagebuffer(dos_header, file_header, option_header, section_headers);

	return 0;
}
