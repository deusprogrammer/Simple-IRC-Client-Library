// IRC Client.cpp : Defines the entry point for the console application.
//

#pragma once

#include <stdio.h>
#include "simSock.h"

DWORD WINAPI ReadServerThread(LPVOID lpargs);

void chop(char* buffer)
{
	int len = strlen(buffer);

	if(buffer[len-1]=='\n')
		buffer[len-1] = 0;
	if(buffer[len-2]=='\r')
		buffer[len-2] = 0;
}

bool isNumber(char c)
{
	if(c>=(int)'0' && c<=(int)'9')
		return true;
	else
		return false;
}

bool isNumber(char* string)
{
	int len = strlen(string);

	//printf("Testing %s (%d)\n", string, len);

	for(int i=0; i<len; i++)
	{
		if(!isNumber(string[i]))
			return false;
	}
	return true;
}

class IRC_Reply
{
private:
	char message[1024];
	char username[32];
	char prefix[128];
	char command[32];
	int numericReply;
	char parameters[1024];
	char trailing[1024];
	bool hasTrailing;
	bool hasUser;
	bool isNumericReply;
public:
	IRC_Reply(char* message);
	char* getMessage() {return message;}
	char* getPrefix() {return prefix;}
	char* getCommand() {return command;}
	char* getParameters() {return parameters;}
	char* getTrailing() {if(hasTrailing) return trailing; else return parameters;}
	char* getUsername() {if(hasUser) return username; else return prefix;}	
	int getNumericReply() {if(isNumericReply) return numericReply; else return -1;}
	bool getHasTrailing() {return hasTrailing;}
};

IRC_Reply::IRC_Reply(char* message)
{
	char* p;
	char* pu;
	char* next;
	char* derp;
	
	numericReply = 0;
	isNumericReply = false;
	hasTrailing = false;
	hasUser = false;

	strcpy(this->message, message);

	//Get Prefix
	p = strtok_s(message, " ", &next);
	if(p!=NULL)
	{
		if(*p==':')
			p++;
		strcpy(prefix, p);

		if(strstr(p, "!")!=NULL)
		{
			pu = strtok_s(p, "!", &derp);
			if(pu!=NULL)
			{
				strcpy(username, pu);
				hasUser = true;
			}
		}
	}

	//Get command
	p = strtok_s(NULL, " ", &next);
	if(p!=NULL)
	{
		if(*p==':')
			p++;
		strcpy(command, p);

		if(isNumber(command))
		{
			isNumericReply = true;
			numericReply = atoi(command);
		}
	}

	//Get parameters
	p = strtok_s(NULL, " ", &next);
	if(p!=NULL)
	{
		if(*p==':')
			p++;
		strcpy(parameters, p);
	}

	//Get trailing
	p = strstr(next, ":");
	if(p!=NULL)
	{
		hasTrailing = true;
		strcpy(trailing, p+1);
	}

	//printf("_%s_\n", command);
}

class IRC_Thread
{
private:
	SOCKET parent;
	char channel[1024];
public:
	IRC_Thread(SOCKET parent, char* channel);
	void SendMessage(char* message);
	void SendCommand(char* command);
	char* getChannel() {return channel;}
};

IRC_Thread::IRC_Thread(SOCKET parent, char* channel)
{
	char data[1024];
	this->parent = parent;
	strcpy(this->channel, channel);

	sprintf(data, "JOIN %s\r\n", this->channel);
	if(WriteSocket(parent, data, strlen(data))<=0)
		printf("Something fucked up!\n");
}

void IRC_Thread::SendMessage(char* message)
{
	char data[1024];

	sprintf(data, "PRIVMSG %s :%s\r\n", channel, message);
	//printf("Sending: %s\n", data);
	if(WriteSocket(parent, data, strlen(data))<=0)
		printf("Something fucked up!\n");
}

class IRC_Connection
{
private:
	SOCKET sock;
	IRC_Thread* current;
	IRC_Thread* threads[1024];
	int nThreads;
	char ip_address[32];
	char port[32];
	char username[32];
	char nickname[32];
	char realname[32];
	char password[32];
	bool connected;
	void (*botptr)(LPVOID lpargs);
	void (*replyptr)(IRC_Reply* reply);
public:
	IRC_Connection(char* ip_address, char* port, char* nickname, char* username, char* realname, char* password);
	void Connect();
	void SwitchChannels(char* channel);
	void SendCommand(char* message);
	void Quit(char* message);
	void SetBotHook(void (*botptr)(LPVOID lpargs));
	void SetReplyHook(void (*replyptr)(IRC_Reply* reply));
	bool isConnected() {return connected;}
	friend DWORD WINAPI ReadServerThread(LPVOID lpargs);
};

IRC_Connection::IRC_Connection(char* ip_address, char* port, char* nickname, char* username, char* realname, char* password)
{
	botptr = NULL;
	replyptr = NULL;
	nThreads = 0;
	current = NULL;
	strcpy(this->ip_address, ip_address);
	strcpy(this->port, port);
	strcpy(this->nickname, nickname);
	strcpy(this->username, username);
	strcpy(this->realname, realname);
	if(password!=NULL)
		strcpy(this->password, password);
	else
		strcpy(this->password, "");
}

void IRC_Connection::Connect()
{
	char data[1024];
	if(OpenClientSocket(&sock, ip_address, port, TCP)==-1)
	{
		printf("Cannot open socket!\n");
		connected = false;
		return;
	}

	connected = true;

	printf("Connected to %s on port %s...\n", ip_address, port);

	CreateThread(NULL, 0, ReadServerThread, this, 0, NULL);

	sprintf(data, "NICK %s\r\n", nickname);
	WriteSocket(sock, data, strlen(data));
	Sleep(500);
	sprintf(data, "USER %s 0 * :%s\r\n", username, realname);
	WriteSocket(sock, data, strlen(data));
	Sleep(500);
}

void IRC_Connection::SwitchChannels(char* channel)
{
	for(int i=0; i<nThreads; i++)
	{
		if(strcmpi(threads[i]->getChannel(), channel)==0)
		{
			current = threads[i];
			break;
		}
	}
}

void IRC_Connection::SendCommand(char* message)
{
	char* p;
	char* arguments;
	char copy[1024];

	sprintf(copy, "%s\r\n", message);

	if(message[0]=='/')
	{
		//printf("Message is a command\n");
		p = strtok_s(message, " ", &arguments);
		if(strcmpi(p, "/join")==0)
		{
			//printf("Message is a JOIN\n");
			current = threads[nThreads++] = new IRC_Thread(this->sock, arguments);
		}
		else
		{
			p = copy + 1;
			//printf("Message: %s\n", p);
			if(WriteSocket(this->sock, p, strlen(p))<=0)
				printf("Something fucked up!\n");
		}
	}
	else
	{
		//printf("Message is a privmsg\n");
		if(current==NULL)
		{
			printf("Not in a channel!\n");
			return;
		}
		current->SendMessage(message);
	}
}

void IRC_Connection::SetBotHook(void (*botptr)(LPVOID lpargs))
{
	this->botptr = botptr;
}

void IRC_Connection::SetReplyHook(void (*replyptr)(IRC_Reply* reply))
{
	this->replyptr = replyptr;
}

void IRC_Connection::Quit(char* message)
{
	char data[1024];

	sprintf(data, "QUIT :%s\r\n", message);
	WriteSocket(sock, data, strlen(message));

	connected = false;
}

struct Bot_Struct
{
	IRC_Connection* conn;
	IRC_Reply* reply;
};

DWORD WINAPI ReadServerThread(LPVOID lpargs)
{
	IRC_Connection* parent;
	Bot_Struct bs;
	int bytes;
	int num;
	char data[1024];
	char* next;
	SOCKET sock;
	IRC_Reply* reply;
	
	parent = (IRC_Connection*)lpargs;
	sock = parent->sock;
	while((bytes = ReadLineSocket(sock, data, 1024))>0)
	{
		data[bytes] = 0;
		chop(data);
		reply = new IRC_Reply(data);
		num = reply->getNumericReply();

		if(strcmpi(reply->getCommand(), "privmsg")==0)
			printf("%s: %s\n", reply->getUsername(), reply->getTrailing());
		else if(strcmpi(reply->getCommand(), "quit")==0)
			printf("%s disconnected: %s\n", reply->getUsername(), reply->getTrailing());
		else if(strcmpi(reply->getCommand(), "join")==0)
			printf("%s joined channel %s\n", reply->getUsername(), reply->getParameters());
		else if(strcmpi(reply->getCommand(), "topic")==0)
			printf("%s changed the topic to \"%s\"\n", reply->getUsername(), reply->getTrailing());
		else if(strcmpi(reply->getPrefix(), "ERROR")==0)
			printf("ERROR\n");
		else if(strcmpi(reply->getPrefix(), "PING")==0)
		{
			printf("Sending keep alive...\n");
			sprintf(data, "PONG :%s\r\n", reply->getCommand());
			printf("%s", data);
			WriteSocket(sock, data);
		}
		else if((num>=1 && num<=5) || (num>=370 && num<=380) || (num>=250 && num<=270))
			printf("%s\n", reply->getTrailing());
		else
			printf("%s\n", reply->getTrailing());

		//If there is a reply hook present, detour to that function
		if(parent->replyptr!=NULL)
			parent->replyptr(reply);

		//If there is a bot hook present, detour to that function
		if(parent->botptr!=NULL)
		{
			bs.reply = reply;
			bs.conn = parent;
			parent->botptr(&bs);
		}

		delete reply;
	}
	printf("Socket disconnected!\n");
	parent->connected = false;

	ExitThread(0);
}
