

#include "json.h"

#include "utils.h"
#include "FileHelper.h"

MyJson::MyJson() {

}


MyJson::~MyJson() {

}


MyJson::MyJson(string fn) {
	fromFile(fn);
}

string MyJson::fromFile(string fn) {
	char* file = 0;
	int filesize = 0;

	int ret = 0;
	
	ret = FileHelper::fileReader(JSON_CONFIG_FILENAME, &file, &filesize);
	if (ret && filesize > 0)
	{
		string json = string(file, filesize);
		removeChar(json, ' ');
		removeChar(json, '\t');
		m_json = json;
		delete file;
	}
	else {
		m_json = "";
	}
	return m_json;
}

string MyJson::insert(string k, string v, int t) {
	int pos = 0;
	string value = getjsonValue(k, t, &pos);
	if (value == "")
	{
		if (t == JSON_TYPE_INT)
		{
			char append[1024];
			string format = "\"%s\":%s";
			wsprintfA(append, format.c_str(), k.c_str(), v.c_str());
			if (m_json.size())
			{
				m_json.append(",");
			}
			m_json.append(append);

		}
		else if (t == JSON_TYPE_STRING)
		{
			string append = string("\"") + k + "\":\"" + v + "\"";
			if (m_json.size())
			{
				m_json.append(",");
			}
			m_json.append(append);
		}
	}else if (value != "" && value != v)
	{
		m_json.replace(pos, value.size(), v);
	}

	return m_json;
}

int MyJson::saveFile() {
	int ret = 0;
	ret = FileHelper::fileWriter(JSON_CONFIG_FILENAME, (char*)m_json.c_str(),m_json.size(),FALSE);
	return ret;
}



string MyJson::getjsonValue(string  key, int type,int *position) {

	string data = m_json;

	string strkey = "\"" + key + "\"";
	SIZE_T pos = data.find(strkey);
	if (pos != data.npos)
	{
		pos += strkey.size();
		SIZE_T p = data.find(":", pos );
		if (p != data.npos)
		{
			p++;
			if (type == JSON_TYPE_STRING )
			{
				SIZE_T prev = data.find("\"", p );
				if (prev != data.npos)
				{
					prev++;
					SIZE_T sur = data.find("\"", prev );
					if (sur!= data.npos)
					{
						string v = data.substr(prev , sur-prev);
						*position = prev;
						return v;
					}
				}
			}
			else if (type == JSON_TYPE_INT)
			{
				SIZE_T prev = p ;

				SIZE_T sur = data.find(",", prev );
				if (sur != data.npos)
				{
					//string v = data.substr(prev, sur ); 包含sur所在的字符
					string v = data.substr(prev, sur - prev);
					*position = prev;
					return v;
				}
				else {
					string v = data.substr(prev);
					*position = prev;
					return v;
				}
			}
		}
	}
	return "";
}



string MyJson::setjsonValue(string k, string  v, int type) {

	int pos = 0;
	string value = getjsonValue(k, type,&pos);
	if (value == "")
	{
		insert(k, v, type);
	}
	else {
		m_json.replace(pos, value.size(), v);
	}
	return m_json;
}