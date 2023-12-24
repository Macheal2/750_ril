#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* begin: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */
#include <stdbool.h>
/* end: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <termios.h>
#include <pthread.h>

#define LOG_NDEBUG 0
#define LOG_TAG "RIL-PPPD"
#include "getdevinfo.h"
#include "meig-log.h"
#include "ril_common.h"

/* begin: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
#ifdef SETUP_DATA_CALL_OPTIMIZATION
#define POLL_RESULT_TIMEOUT_IN_MS 100
#define CHAT_TIMEOUT_IN_MS 800
#else
#define POLL_RESULT_TIMEOUT_IN_MS 200
#define CHAT_TIMEOUT_IN_MS 1000
#endif
/* end: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */

int notifyDataCallProcessExit(void);
extern char *g_ppp_number;
extern MODEM_INFO  curr_modem_info;
extern int debug_enable;
static  int meig_mux_enabled = 0;

#define MAX_PATH 256
#define USBID_LEN 4
struct meig_usb_id_struct {
    unsigned short vid;
    unsigned short pid;
    unsigned short at_inf;
    unsigned short ppp_inf;

};
static char usbdevice_pah[MAX_PATH];

#define USB_AT_INF 0
#define USB_PPP_INF 1
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

/* begin: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */
#define EXEC_BIN_PATH_COUNT 4
#define EXEC_FILE_PATH_LEN 32
static char *execBinPath[EXEC_BIN_PATH_COUNT] = {
    "/system/bin",
    "/vendor/bin",
    "/oem/bin",
    "/product/bin",
};
char s_pppd_path[EXEC_FILE_PATH_LEN] = {0};
char s_chat_path[EXEC_FILE_PATH_LEN] = {0};
/* end: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */

static int meig_is_digit(const char *pdigit)
{
    const char *pcur = pdigit;
    if (NULL == pcur) {
        return 0;
    }
    for (pcur = pdigit; (NULL != pcur) && (0 != *pcur); pcur++) {
        if ((*pcur < '0') || (*pcur > '9')) {
            return 0;
        }
    }
    return 1;
}

static int is_chat_alive(void)
{
#define BIN_CHAT "/system/bin/chat"
    int ret = 0;
    int nmsz = 0;
    DIR *pDir = NULL;
    struct dirent *ent = NULL;
    char dir[MAX_PATH] = {0};
    char filename[MAX_PATH] = {0};
    char link_path[MAX_PATH] = {0};

    strcat(dir, "/proc");
    if ((pDir = opendir(dir)) == NULL) {
        LOGE("canot open directory : %s, errno=%d(%s)\n", dir, errno, strerror(errno));
        ret = 0;
        goto out;
    }

    while ((ent = readdir(pDir)) != NULL) {
        if (0 == meig_is_digit((const char *)(ent->d_name))) {
            continue;
        }
        sprintf(filename, "%s/%s/exe", dir, ent->d_name);
        memset(link_path, 0, sizeof(link_path));
        nmsz = readlink(filename, link_path, MAX_PATH);
        if (nmsz <= 0) {
            continue;
        }
        link_path[nmsz] = 0;
        if (!strncmp(link_path, BIN_CHAT, strlen(BIN_CHAT))) {
            ret = 1;
            goto out;
        }
    }
out:
    return ret;
}


static int idusb2hex(char idusbinfo[USBID_LEN])
{
    int i;
    int value = 0;
    for (i = 0; i < USBID_LEN; i++) {
        if (idusbinfo[i] < 'a')
            value |= ((idusbinfo[i] - '0') << ((3 - i)*4));
        else
            value |= ((idusbinfo[i] - 'a' + 10) << ((3 - i)*4));
    }
    return value;
}


void meig_set_autosuspend(int enable)
{
    if (usbdevice_pah[0]) {
        char shell_command[MAX_PATH+32];
        snprintf(shell_command, sizeof(shell_command), "echo %s > %s/power/control", enable ? "auto" : "on", usbdevice_pah);
        system(shell_command);
        LOGD("%s", shell_command);
        LOGD("%s %s", __func__, enable ? "auto" : "off");
    }
}

static int chat(int fd, const char *at, const char *expect, int timeout, char **response)
{
    int ret, retry = 0;
    static char buf[128];

    if (response)
        *response = NULL;

    tcflush(fd, TCIOFLUSH);
    LOGD("chat --> %s", at);
    do {
        ret = write(fd, at, strlen(at));
    } while (ret < 0 && errno == EINTR);

    if (ret <= 0) {
        LOGD("chat write error on stdout: %s(%d) ", strerror(errno), errno);
        return errno ? errno : EINVAL;
    }

    while(timeout > 0) {
        struct pollfd poll_fd = {fd, POLLIN, 0};
/* begin: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
        if(poll(&poll_fd, 1, POLL_RESULT_TIMEOUT_IN_MS) <= 0) {
            if (errno == ETIMEDOUT || 0 == errno || EAGAIN == errno) {
                timeout -= POLL_RESULT_TIMEOUT_IN_MS;
                continue;
            } else if(errno != EINTR) {
                LOGE("chat poll error on stdin: %s(%d) ", strerror(errno), errno);
                return errno ? errno : EINVAL;
            }
        }
/* end: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */

        if(poll_fd.revents && (poll_fd.revents & POLLIN)) {
            memset(buf, 0, sizeof(buf));
            usleep(100*1000);
            if(read(fd, buf, sizeof(buf)-1) <= 0) {
                LOGD("chat read error on stdin: %s(%d) ", strerror(errno), errno);
                return errno ? errno : EINVAL;
            }
            LOGD("chat %zd <-- %s", strlen(buf), buf);
            if(strstr(buf, expect)) {
                if (response)
                    *response = strstr(buf, expect);
                return 0;
            }
        }
    }

    return errno ? errno : EINVAL;
}

#if 0
static pid_t meig_get_pid(const char *pname)
{
    DIR *pDir;
    struct dirent* ent = NULL;
    pid_t pid = 0;
    char *linkname = (char *) malloc (MAX_PATH + MAX_PATH);
    char *filename = linkname + MAX_PATH;
    int filenamesize;

    if (!linkname)
        return 0;

    pDir = opendir("/proc");
    if (pDir == NULL)  {
        LOGE("Cannot open directory: /proc, errno: %d (%s)", errno, strerror(errno));
        return 0;
    }

    while ((ent = readdir(pDir)) != NULL)  {
        int i = 0;
        //LOGD("%s", ent->d_name);
        while (ent->d_name[i]) {
            if ((ent->d_name[i] < '0')  || (ent->d_name[i] > '9'))
                break;
            i++;
        }

        if (ent->d_name[i]) {
            //LOGD("%s not digit", ent->d_name);
            continue;
        }

        sprintf(linkname, "/proc/%s/exe", ent->d_name);
        filenamesize = readlink(linkname, filename, MAX_PATH-1);
        if (filenamesize > 0) {
            filename[filenamesize] = 0;
            if (!strcmp(filename, pname)) {
                pid = atoi(ent->d_name);
                LOGD("%s -> %s", linkname, filename);
            }
        } else {
            //LOGD("readlink errno: %d (%s)", errno, strerror(errno));
        }
    }
    closedir(pDir);
    free(linkname);

    return pid;
}
#endif

static pid_t meig_pppd_pid = 0;
static int meig_pppd_quit = 0;
static pthread_t meig_pppd_thread;
static int pppd_create_thread(pthread_t * thread_id, void * thread_function, void * thread_function_arg )
{
    static pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(thread_id, &thread_attr, thread_function, thread_function_arg)!=0) {
        LOGE("%s %s errno: %d (%s)", __FILE__, __func__, errno, strerror(errno));
        return 1;
    }
    pthread_attr_destroy(&thread_attr); /* Not strictly necessary */
    return 0; //thread created successfully
}

static void meig_sleep(int sec)
{
    int msec = sec * 1000;
    while (!meig_pppd_quit && (msec > 0)) {
        msec -= 200;
        usleep(200*1000);
    }
}
/* begin: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
static void meig_sleep_ms(int msec)
{
    while (!meig_pppd_quit && (msec > 0)) {
        msec -= 200;
        usleep(200*1000);
    }
}
#ifdef SETUP_DATA_CALL_OPTIMIZATION
static int s_chat_fail_count = 0;
int get_chat_fail_count() {
    return s_chat_fail_count;
}
void set_chat_fail_count(int count) {
    s_chat_fail_count = count;
}
#endif
/* end: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */

static char s_ppp_modemport[32];
/*[zhaopf@meigsmart-2020-0618]add for ipv6 support { */
static char s_ppp_protocol[32];
/*[zhaopf@meigsmart-2020-0618]add for ipv6 support } */
static char s_ppp_user[128];
static char s_ppp_password[128];
static int  s_ppp_auth_type = 0;
static char s_ppp_number[32];
static void* pppd_thread_function(void*  arg)
{
    char **argvv = (char **)arg;

    RLOGD("%s %s|%s|%s|%s|%d|%s enter", __func__, s_ppp_modemport, s_ppp_user, s_ppp_password, s_ppp_protocol, s_ppp_auth_type, s_ppp_number);

    //LOGD("modemport = %s", modemport);
    //LOGD("user = %s", user);
    //LOGD("password = %s", password);
    //LOGD("auth_type = %s", auth_type);

    while (!meig_pppd_quit) {
        char ttyname[10];
        char serialdevname[32];
        pid_t child_pid;
        int modem_fd, fdflags;
        char *response;
        strcpy(serialdevname, s_ppp_modemport);

        if(HISI != curr_modem_info.info.sltn_type) {
            int modembits = TIOCM_DTR;
            struct termios  ios;

            //make sure modem is not in data mode!
            modem_fd = open (serialdevname, O_RDWR | O_NONBLOCK);
            if (modem_fd == -1) {
                RLOGE("failed to open %s  errno: %d (%s)\n",  serialdevname, errno, strerror(errno));
                meig_sleep(3);
                continue;
            }

            fdflags = fcntl(modem_fd, F_GETFL);
            if (fdflags != -1)
                fcntl(modem_fd, F_SETFL, fdflags | O_NONBLOCK);
            /* disable echo on serial ports */
            tcgetattr( modem_fd, &ios );
            cfmakeraw(&ios);
            ios.c_lflag = 0;  /* disable ECHO, ICANON, etc... */
            cfsetispeed(&ios, B115200);
            cfsetospeed(&ios, B115200);
            tcsetattr( modem_fd, TCSANOW, &ios );

            ioctl(modem_fd, (0 ? TIOCMBIS: TIOCMBIC), &modembits); //clear DTR
/* begin: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
            if (chat(modem_fd, "AT\r\n", "OK", CHAT_TIMEOUT_IN_MS, NULL)) {
                if (meig_mux_enabled) {
                    close(modem_fd);
                    meig_sleep(3);
                } else {
                    ioctl(modem_fd, (1 ? TIOCMBIS: TIOCMBIC), &modembits);
#ifdef SETUP_DATA_CALL_OPTIMIZATION
                    meig_sleep_ms(600);
#else
                    meig_sleep(1);
#endif
                    ioctl(modem_fd, (0 ? TIOCMBIS: TIOCMBIC), &modembits);
#ifdef SETUP_DATA_CALL_OPTIMIZATION
                    meig_sleep_ms(600);
#else
                    meig_sleep(1);
#endif
                    close(modem_fd);
                }
#ifdef SETUP_DATA_CALL_OPTIMIZATION
                s_chat_fail_count++;
                RLOGD("%s chat_fail_count = %d, err = %d, %s", __func__, s_chat_fail_count, errno, strerror(errno));
#endif
                continue;
            }
/* end: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
            /*yufeilong add for check registration status before PPP dialing 20220711 start*/
             if(!checkIfPSReady()){
                RLOGD("network registration failed!\n");
                continue;

             }
            /*yufeilong add for check registration status before PPP dialing 20220711 end*/

            close(modem_fd);
        } //not HISI

        child_pid = fork();
        if (0 == child_pid) { //this is the child_process
            int argc = 0;
            const char *argv[80] = {"pppd", "115200", "nodetach", "nolock", "debug", "dump", "nocrtscts", "modem", "hide-password",
                                    "usepeerdns", "noipdefault", "novj", "novjccomp", "noccp", "defaultroute", "ipcp-accept-local", "ipcp-accept-remote", "ipcp-max-failure", "30",
                                    "ipcp-max-configure", "30", /*"connect-delay", "5000",*/ "lcp-restart", "1", "lcp-max-terminate" ,"1" ,
                                    //"connect", "/etc/ppp/init.meig-pppd chat connect",
                                    //"disconnect","/etc/ppp/init.meig-pppd chat disconnect",
                                    NULL
                                   };
            char *ppp_dial_number = NULL;
            while (argv[argc]) argc++;
            argv[argc++] = serialdevname;
            /*[zhaopf@meigsmart-2020-0617]add for ipv6 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_5_1_SDK_VERSION)
            if(NULL != strcasestr(s_current_protocol, "V6")){
                argv[argc++] = "+ipv6";
            }
#endif
            /*[zhaopf@meigsmart-2020-0617]add for ipv6 support } */
            if (s_ppp_user[0]) {
                argv[argc++] = "user";
                argv[argc++] = s_ppp_user;
            }
            if (s_ppp_user[0] && s_ppp_password[0]) {
                argv[argc++] = "password";
                argv[argc++] = s_ppp_password;
            }
            if (s_ppp_user[0] && s_ppp_password[0] ) {
                switch(s_ppp_auth_type) {
                case AUTH_NONE:
                    argv[argc++] = "refuse-pap";
                    argv[argc++] = "refuse-chap";
                    break;
                case AUTH_PAP:
                    argv[argc++] = "refuse-chap";
                    break;
                case AUTH_CHAP:
                    argv[argc++] = "refuse-pap";
                    break;
                case AUTH_PAP_OR_CHAP:
                    break;
                default:
                    break;
                }
                argv[argc++] = "refuse-eap";
                argv[argc++] = "refuse-mschap";
                argv[argc++] = "refuse-mschap-v2";
            }
            /*yufeilong add for support SLM770 PPP dialing 20220711 start*/
            /* begin: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */
            asprintf(&ppp_dial_number,
                     "''%s -s -v ABORT BUSY ABORT \"NO CARRIER\" ABORT \"NO DIALTONE\" ABORT ERROR ABORT \"NO ANSWER\" TIMEOUT 30 \'\' \rAT OK ATS0=0 OK ATE0V1 OK ATD%s CONNECT''", s_chat_path, s_ppp_number);
            /* end: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */
            /*yufeilong add for support SLM770 PPP dialing 20220711 end*/
            argv[argc++] = "connect";
            argv[argc++] = ppp_dial_number;
            argv[argc] = NULL;
            if(debug_enable) {
                RLOGD(" ====argv list begin===== \n");
                /*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support { */
                int i;
                for(i = 0; i < argc; i++) {
                    RLOGD(" %s ", argv[i]);
                }
                /*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support } */
                RLOGD(" ====argv list end===== \n");
            }
            /* begin: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */
            if (execv(s_pppd_path, (char**) argv)) {
                RLOGE("cannot execve('%s'): %s\n", argv[0], strerror(errno));
                free(ppp_dial_number);
                exit(errno);
            }
            free(ppp_dial_number);
            /* end: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */
            exit(0);
        } else if (child_pid < 0) {
            RLOGE("failed to start ('%s'): %s\n", "pppd", strerror(errno));
            break;
        } else {
            int status, retval = 0;
            meig_pppd_pid = child_pid;
            waitpid(child_pid, &status, 0);
            meig_pppd_pid = 0;
            if (meig_mux_enabled)
                close(modem_fd);
            if (WIFSIGNALED(status)) {
                retval = WTERMSIG(status);
                RLOGD("*** %s: Killed by signal %d retval = %d\n", "pppd", WTERMSIG(status), retval);
            } else if (WIFEXITED(status) && WEXITSTATUS(status) > 0) {
                retval = WEXITSTATUS(status);
                RLOGD("*** %s: Exit code %d retval = %d\n", "pppd", WEXITSTATUS(status), retval);
            }
            if (notifyDataCallProcessExit() || meig_pppd_quit)
                break;
            else
                meig_sleep(3);
        }
    }

    meig_pppd_thread = 0;
    RLOGD("%s exit", __func__);
    pthread_exit(NULL);
    return NULL;
}

/* begin: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */
bool findPPPDExecFile() {
    int i = 0;
    bool isPPPDNeeded = s_pppd_path[0] == '\0';
    bool isChatNeeded = s_chat_path[0] == '\0';
    if (!isPPPDNeeded && !isChatNeeded) {
        RLOGD("%s both paths is set. s_pppd_path = %s, s_chat_path = %s", __FUNCTION__, s_pppd_path, s_chat_path);
        return true;
    }
    for (; i < EXEC_BIN_PATH_COUNT; i++) {
        if (isPPPDNeeded) {
            memset(s_pppd_path, 0, sizeof(s_pppd_path));
            snprintf(s_pppd_path, sizeof(s_pppd_path), "%s/%s", execBinPath[i], "pppd");
            if (!access(s_pppd_path, X_OK)) {
                RLOGD("%s find pppd path: %s", __FUNCTION__, s_pppd_path);
                isPPPDNeeded = false;
            }
        }
        if (isChatNeeded) {
            memset(s_chat_path, 0, sizeof(s_chat_path));
            snprintf(s_chat_path, sizeof(s_chat_path), "%s/%s", execBinPath[i], "chat");
            if (!access(s_chat_path, X_OK)) {
                RLOGD("%s find chat path: %s", __FUNCTION__, s_chat_path);
                isChatNeeded = false;
            }
        }
    }
    RLOGD("%s isPPPDNeeded = %d, isChatNeeded = %d", __FUNCTION__, isPPPDNeeded, isChatNeeded);
    if (isPPPDNeeded) {
        memset(s_pppd_path, 0, sizeof(s_pppd_path));
        return false;
    }
    if (isChatNeeded) {
        memset(s_chat_path, 0, sizeof(s_chat_path));
        return false;
    }
    return true;
}
/* end: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */

int meig_pppd_stop(int signo);
/*[zhaopf@meigsmart-2020-0618]modify for ipv6 support { */
int meig_pppd_start(const char *modemport, const char *user, const char *password, const char* protocol, int auth_type, const char *ppp_number)
{
/*[zhaopf@meigsmart-2020-0618]modify for ipv6 support } */
    meig_pppd_stop(SIGKILL);

    RLOGD("modemport = %s", modemport);
    RLOGD("user = %s", user);
    RLOGD("password = %s", password);
    RLOGD("auth_type = %d", auth_type);

    s_ppp_modemport[0] = s_ppp_user[0] = s_ppp_password[0]  = s_ppp_number[0] = '\0';
    if (modemport != NULL) strncpy(s_ppp_modemport, modemport, sizeof(s_ppp_modemport) - 1);
    if (user != NULL) strncpy(s_ppp_user, user, sizeof(s_ppp_user) - 1);
    if (password != NULL) strncpy(s_ppp_password, password, sizeof(s_ppp_password) - 1);
    /*[zhaopf@meigsmart-2020-0618]modify for ipv6 support { */
    if (protocol != NULL) strncpy(s_ppp_protocol, protocol, sizeof(s_ppp_protocol) - 1);
    /*[zhaopf@meigsmart-2020-0618]modify for ipv6 support } */

    s_ppp_auth_type = auth_type;
    if (ppp_number != NULL) strncpy(s_ppp_number, ppp_number, sizeof(s_ppp_number) - 1);

    /* begin: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */
    findPPPDExecFile();
    if (s_pppd_path[0] == '\0') {
        RLOGE("pppd do not exist in any of the bin path or is not Execute!");
        return (-ENOENT);
    }
    if (s_chat_path[0] == '\0') {
        RLOGE("chat do not exist in any of the bin path or is not Execute!");
        return (-ENOENT);
    }
    /* end: modified by dongmeirong for pppd find for SHIYUAN_LIUHUAN 20210622 */
    if (access("/etc/ppp/ip-up", X_OK)) {
        RLOGE("/etc/ppp/ip-up do not exist or is not Execute!");
        return (-ENOENT);
    }

    meig_pppd_quit = 0;
    if (!pppd_create_thread(&meig_pppd_thread, pppd_thread_function, NULL))
        return getpid();
    else
        return -1;
}

int meig_pppd_stop(int signo)
{
    unsigned int kill_time = 15000;
    int retry = 0;
    meig_pppd_quit = 1;

    if (meig_pppd_pid == 0 && meig_pppd_thread == 0)
        return 0;
#if 1 //wait for chat over, or pppd will kill all progresses in our progresses group
    for (retry = 0; retry < 10; retry++) { // modified retry times from 50 to 10, 50s is too long
        if (0 == is_chat_alive()) {
            break;
        }
        RLOGD("wait for chat over!!!\n");
        sleep(1);
    }
#endif

    if (meig_pppd_pid != 0) {
        if (fork() == 0) {//kill may take long time, so do it in child process
            int kill_time = 10;
            kill(meig_pppd_pid, signo);
            while(kill_time-- && !kill(meig_pppd_pid, 0)) //wait pppd quit
                sleep(1);
            if (signo != SIGKILL && !kill(meig_pppd_pid, 0))
                kill(meig_pppd_pid, SIGKILL);
            exit(0);
        }
    }

    do {
        usleep(100*1000);
        kill_time -= 100;
    } while ((kill_time > 0) && (meig_pppd_pid != 0 || meig_pppd_thread != 0));

    LOGD("%s cost %d msec", __func__, (15000 - kill_time));
    return 0;
}
