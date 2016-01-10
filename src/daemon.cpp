#include <algorithm>
#include <cstring>
#include <cctype>
#include <functional>
#include <locale>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <vector>
#include <algorithm>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <map>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>

using namespace std;

#define LOG_FILE_NAME           "daemon"
#define UPDATER_SLEEP_SEC       2

bool g_daemon = false;

static pthread_mutex_t s_shutdownLock;
static bool s_shutdown = false;
static map<string, int> s_statistics;

/**
 * Returns true if char is not alphanumeric
 */
inline bool IsNotAlphaNumChar(const char c)
{
	if (c != '\r' && c != '\n' && (c < 32 || c > 125) )
		return true;
	return false;
}

/**
 * Print debug message
 */
void DebugPrint(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char buff[1024]; // get rid of this hard-coded buffer
    char tmp[1024];

    snprintf(tmp, 1023, "%s\n", format);
    vsnprintf(buff, 1023, tmp, args);
    va_end(args);

    // replace non alpha characters
    string out(buff);
    replace_if(out.begin(), out.end(), IsNotAlphaNumChar, '.');

    if (!g_daemon)
    {
    	printf("%s", out.c_str());
    }
    else
    {
    	time_t t = time(NULL);
    	struct tm tm = *localtime(&t);

    	char filename[FILENAME_MAX];
    	sprintf(filename, "/tmp/" LOG_FILE_NAME ".%d-%d-%d.log", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);

    	FILE *fp;
    	fp=fopen(filename, "a");
    	if (fp != NULL)
    	{
    		fprintf(fp, "%s", out.c_str());
    		fclose(fp);
    	}
    	else
    	{
    		printf("ERROR: could not create log file\n");
    	}
    }
}

/**
 * Check for shutdown
 */
static bool DoShutdown()
{
	bool exit = false;
	pthread_mutex_lock(&s_shutdownLock);
	if (s_shutdown)
		exit = true;
	pthread_mutex_unlock(&s_shutdownLock);

	return exit;
}

static bool SleepAndCheckForShutdown(int seconds)
{
	if (seconds < 0)
		seconds = 0;

	bool run = true;
	int n = 0;
	while (true)
	{
		usleep(500000);
		n++;

		run = !DoShutdown();
		if (!run || n > (seconds * 2))
			break;
	}

	return run;
}

static void *MainProcess(void * arg)
{
	do
	{

		DebugPrint("Sleeping ..\n");
	} while (SleepAndCheckForShutdown(UPDATER_SLEEP_SEC));

	return NULL;
}

// Define the function to be called when ctrl-c (SIGINT) signal is sent to process
void signal_callback_handler(int signum)
{
   DebugPrint("\nCaught signal %d\n\n", signum);

   pthread_mutex_lock(&s_shutdownLock);
   s_shutdown = true;
   pthread_mutex_unlock(&s_shutdownLock);
}

void PrintHelp()
{
	printf("Options: \n");
	printf("	d - daemon mode\n");
	printf("	h - print this help message\n");
}
int main(int argc, char *argv[])
{
	int c;

	opterr = 0;
	// d - daemon, h - help
	while ((c = getopt(argc, argv, "dh")) != -1)
	{
		switch (c)
		{
		case 'd':
			g_daemon = true;
			break;
		case 'h':
			PrintHelp();
			return EXIT_SUCCESS;
			break;
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Unknown option '-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return EXIT_FAILURE;
		default:
			abort();
		}
	}

	// Register signal and signal handler
	signal(SIGINT, signal_callback_handler);

	if (g_daemon)
	{
		cout << argv[0] << " starting in daemon mode.." << endl;
	}
	else
	{
		cout << argv[0] << " started" << endl;
	}

	if (g_daemon)
	{
		pid_t pid, sid;
	   //Fork the Parent Process
		pid = fork();

		if (pid < 0) { exit(EXIT_FAILURE); }

		//We got a good pid, Close the Parent Process
		if (pid > 0) { exit(EXIT_SUCCESS); }

		//Change File Mask
		umask(0);

		//Create a new Signature Id for our child
		sid = setsid();
		if (sid < 0) { exit(EXIT_FAILURE); }

		//Change Directory
		//If we cant find the directory we exit with failure.
		if ((chdir("/")) < 0) { exit(EXIT_FAILURE); }

		//Close Standard File Descriptors
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

    //----------------
    //Main Process
    //----------------
	pthread_t t;
	pthread_create(&t, NULL, &MainProcess, NULL);
	pthread_join(t, NULL);

	DebugPrint("Shutting down..");

	return EXIT_SUCCESS;
}
