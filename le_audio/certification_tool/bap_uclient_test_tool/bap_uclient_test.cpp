/***********************************************************************
 *
 *  Copyright (c) 2014-2015, 2020 The Linux Foundation. All rights reserved.
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *

******************************************************************************/


/******************************************************************************
******
 *
 *  Filename:      bap_uclient_test.cpp
 *
 *  Description:   bap unicast client test application
 *

*******************************************************************************
****/


#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <map>
#include <iomanip>
#include <private/android_filesystem_config.h>
#include <android/log.h>
#include <hardware/bt_gatt_types.h>
#include <hardware/hardware.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_bap_uclient.h>
#include <hardware/bt_pacs_client.h>
#include <hardware/bt_ascs_client.h>

#include <signal.h>
#include <time.h>

#include <base/bind.h>
#include <base/callback.h>

using bluetooth::Uuid;

constexpr uint8_t ASE_DIRECTION_SINK           = 0x01 << 0;
constexpr uint8_t ASE_DIRECTION_SRC            = 0x01 << 1;

constexpr uint8_t ASE_SINK_STEREO     = 0x01 << 0;
constexpr uint8_t ASE_SRC_STEREO      = 0x01 << 1;

#ifndef BAP_UNICAST_TEST_APP_INTERFACE
#define BAP_UNICAST_TEST_APP_INTERFACE
/******************************************************************************
******
**  Constants & Macros
*******************************************************************************
*****/

#ifndef TRUE
#define     TRUE       1
#endif
#ifndef FALSE
#define     FALSE      0
#endif

#define PID_FILE "/data/.bdt_pid"

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define CASE_RETURN_STR(const) case const: return #const;


/******************************************************************************
******
**  Local type definitions
*******************************************************************************
*****/


/******************************************************************************
******
**  Static variables
*******************************************************************************
*****/

static unsigned char main_done = 0;
static int status;

#define LE_ACL_MAX_BUFF_SIZE 4096
static int num_frames = 1;
static unsigned long g_delay = 1; /* Default delay before data transfer */
static int count = 1;
static uint16_t g_BleEncKeySize = 16;
static int g_le_coc_if = 0;
static int rcv_itration = 0;
static volatile bool cong_status = FALSE;


/* Main API */
const bt_interface_t* sBtInterface = NULL;

static gid_t groups[] = { AID_NET_BT, AID_INET, AID_NET_BT_ADMIN,
                          AID_SYSTEM, AID_MISC, AID_SDCARD_RW,
                          AID_NET_ADMIN, AID_VPN};

enum {
   DISCONNECT,
   CONNECTING,
   CONNECTED,
   DISCONNECTING
};

static unsigned char bt_enabled = 0;
static int  g_ConnectionState   = DISCONNECT;
static int  g_AdapterState      = BT_STATE_OFF;
static int  g_PairState         = BT_BOND_STATE_NONE;

static int  g_conn_id        = 0;
static int  g_client_if      = 0;
static int  g_server_if      = 0;
static int  g_client_if_scan = 0;
static int  g_server_if_scan = 0;


RawAddress* remote_bd_address;

static uint16_t g_SecLevel = 0;
static bool g_ConnType = TRUE;//DUT is initiating connection

/******************************************************************************
******
**  Static functions
*******************************************************************************
*****/

static void process_cmd(char *p, unsigned char is_job);
//static void job_handler(void *param);
static void bdt_log(const char *fmt_str, ...);
static void l2c_connect(RawAddress bd_addr);
static uint16_t do_l2cap_connect(RawAddress bd_addr);

int GetBdAddr(char *p, RawAddress* pbd_addr);
void bdt_init(void);
int reg_inst_id = -1;
int reg_status = -1;


/******************************************************************************
******
**  ASCS Client Callbacks
*******************************************************************************
*****/


/******************************************************************************
******
**  PACS client Callbacks
*******************************************************************************
*****/



/******************************************************************************
******
**  BAP Unicast client Callbacks
*******************************************************************************
*****/

/******************************************************************************
******
**  Shutdown helper functions
*******************************************************************************
*****/

static void bdt_shutdown(void)
{
    bdt_log("shutdown bdroid test app.\n");
    main_done = 1;
}


/*****************************************************************************
** Android's init.rc does not yet support applying linux capabilities
*****************************************************************************/

static void config_permissions(void)
{
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct cap[2];

    bdt_log("set_aid_and_cap : pid %d, uid %d gid %d", getpid(), getuid(), getgid());

    header.pid = 0;

    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

    setuid(AID_BLUETOOTH);
    setgid(AID_BLUETOOTH);

    header.version = _LINUX_CAPABILITY_VERSION_3;

    cap[CAP_TO_INDEX(CAP_NET_RAW)].permitted |= CAP_TO_MASK(CAP_NET_RAW);
    cap[CAP_TO_INDEX(CAP_NET_ADMIN)].permitted |= CAP_TO_MASK(CAP_NET_ADMIN);
    cap[CAP_TO_INDEX(CAP_NET_BIND_SERVICE)].permitted |= CAP_TO_MASK(CAP_NET_BIND_SERVICE);
    cap[CAP_TO_INDEX(CAP_SYS_RAWIO)].permitted |= CAP_TO_MASK(CAP_SYS_RAWIO);
    cap[CAP_TO_INDEX(CAP_SYS_NICE)].permitted |= CAP_TO_MASK(CAP_SYS_NICE);
    cap[CAP_TO_INDEX(CAP_SETGID)].permitted |= CAP_TO_MASK(CAP_SETGID);
    cap[CAP_TO_INDEX(CAP_WAKE_ALARM)].permitted |= CAP_TO_MASK(CAP_WAKE_ALARM);

    cap[CAP_TO_INDEX(CAP_NET_RAW)].effective |= CAP_TO_MASK(CAP_NET_RAW);
    cap[CAP_TO_INDEX(CAP_NET_ADMIN)].effective |= CAP_TO_MASK(CAP_NET_ADMIN);
    cap[CAP_TO_INDEX(CAP_NET_BIND_SERVICE)].effective |= CAP_TO_MASK(CAP_NET_BIND_SERVICE);
    cap[CAP_TO_INDEX(CAP_SYS_RAWIO)].effective |= CAP_TO_MASK(CAP_SYS_RAWIO);
    cap[CAP_TO_INDEX(CAP_SYS_NICE)].effective |= CAP_TO_MASK(CAP_SYS_NICE);
    cap[CAP_TO_INDEX(CAP_SETGID)].effective |= CAP_TO_MASK(CAP_SETGID);
    cap[CAP_TO_INDEX(CAP_WAKE_ALARM)].effective |= CAP_TO_MASK(CAP_WAKE_ALARM);

    capset(&header, &cap[0]);
    setgroups(sizeof(groups)/sizeof(groups[0]), groups);
}


/*****************************************************************************
**   Logger API
*****************************************************************************/

void bdt_log(const char *fmt_str, ...)
{
    static char buffer[1024];
    va_list ap;

    va_start(ap, fmt_str);
    vsnprintf(buffer, 1024, fmt_str, ap);
    va_end(ap);

    fprintf(stdout, "%s\n", buffer);
}

/******************************************************************************
*
 ** Misc helper functions

*******************************************************************************/
static const char* dump_bt_status(int status)
{
    switch(status)
    {
        CASE_RETURN_STR(BT_STATUS_SUCCESS)
        CASE_RETURN_STR(BT_STATUS_FAIL)
        CASE_RETURN_STR(BT_STATUS_NOT_READY)
        CASE_RETURN_STR(BT_STATUS_NOMEM)
        CASE_RETURN_STR(BT_STATUS_BUSY)
        CASE_RETURN_STR(BT_STATUS_UNSUPPORTED)

        default:
            return "unknown status code";
    }
}


/******************************************************************************
*
 ** Console helper functions

*******************************************************************************/

void skip_blanks(char **p)
{
    while (**p == ' ')
    (*p)++;
}

uint32_t get_int(char **p, int DefaultValue)
{
    uint32_t Value = 0;
    unsigned char   UseDefault;

    UseDefault = 1;
    skip_blanks(p);

    while ( ((**p)<= '9' && (**p)>= '0') )
    {
        Value = Value * 10 + (**p) - '0';
        UseDefault = 0;
        (*p)++;
    }
   if (UseDefault)
       return DefaultValue;
   else
       return Value;
}

int get_signed_int(char **p, int DefaultValue)
{
    int    Value = 0;
    unsigned char   UseDefault;
    unsigned char  NegativeNum = 0;

    UseDefault = 1;
    skip_blanks(p);

    if ((**p) == '-')
    {
        NegativeNum = 1;
        (*p)++;
    }
    while ( ((**p)<= '9' && (**p)>= '0') )
    {
        Value = Value * 10 + (**p) - '0';
        UseDefault = 0;
        (*p)++;
    }

    if (UseDefault)
        return DefaultValue;
    else
        return ((NegativeNum == 0)? Value : -Value);
}

void get_str_1(char **p, char *Buffer)
{
    skip_blanks(p);
    while (**p != 0 && **p != '\0')
    {
        *Buffer = **p;
        (*p)++;
        Buffer++;
    }

    *Buffer = 0;
}

void get_str(char **p, char *Buffer)
{
    skip_blanks(p);
    while (**p != 0 && **p != ' ')
    {
        *Buffer = **p;
        (*p)++;
        Buffer++;
    }

    *Buffer = 0;
}



#define is_cmd(str) ((strlen(str) == strlen(cmd)) && strncmp((const char *)&cmd, str, strlen(str)) == 0)
#define if_cmd(str)  if (is_cmd(str))

typedef void (t_console_cmd_handler) (char *p);

typedef struct {
    const char *name;
    t_console_cmd_handler *handler;
    const char *help;
    unsigned char is_job;
} t_cmd;

void do_help(char *p);
void do_quit(char *p);
void do_init(char *p);
void do_enable(char *p);
void do_disable(char *p);
void do_cleanup(char *p);
void do_pairing(char *p);
void do_pacs_discovery(char *p);
void do_ascs_discovery(char *p);
void do_bap_connect(char *p);
void do_bap_disconnect(char *p);
void do_bap_start(char *p);
void do_bap_stop(char *p);
void do_bap_disc_in_connecting(char *p);
void do_bap_disc_in_starting(char *p);
void do_bap_disc_in_stopping(char *p);
void do_bap_stop_in_starting(char *p);
void do_bap_update_stream(char *p);

/*******************************************************************
 *
 *  CONSOLE COMMAND TABLE
 *
*/

const t_cmd console_cmd_list[] =
{
    /*
     * INTERNAL
     */

    { "help", do_help, "lists all available console commands", 0 },
    { "quit", do_quit, "", 0},

    /*
     * API CONSOLE COMMANDS
     */

     /* Init and Cleanup shall be called automatically */
    { "enable", do_enable, "cmd :: enable", 0 },
    { "disable", do_disable, "cmd  :: disable", 0 },
    { "pair", do_pairing, "cmd :: pair <BdAddr as 00112233445566>", 0 },
    { "pacs_discovery", do_pacs_discovery, "cmd :: pacs_discovery <BdAddr>", 0 },
    { "ascs_discovery", do_ascs_discovery, "cmd :: ascs_discovery <BdAddr>", 0 },
    { "bap_connect", do_bap_connect, "cmd :: bap_connect <CodecConfig> <AudioConfig> <BdAddr> <profile> <direction> <context>", 0 },
    { "bap_disconnect", do_bap_disconnect, "cmd :: bap_disconnect <BdAddr> <profile> <direction> <context>", 0 },
    { "bap_start", do_bap_start, "cmd :: bap_start <BdAddr> <profile> <direction> <context>", 0 },
    { "bap_stop", do_bap_stop, "cmd :: bap_stop <BdAddr> <profile> <direction> <context>", 0 },
    { "bap_disc_in_connecting", do_bap_disc_in_connecting, "cmd :: bap_disc_in_connecting <CodecConfig> <AudioConfig> <BdAddr> <profile> <direction> <context>", 0 },
    { "bap_disc_in_starting", do_bap_disc_in_starting, "cmd :: bap_disc_in_starting <BdAddr> <profile> <direction> <context>", 0 },
    { "bap_disc_in_stopping", do_bap_disc_in_stopping, "cmd :: bap_disc_in_stopping <BdAddr> <profile> <direction> <context>", 0 },
    { "bap_stop_in_starting", do_bap_stop_in_starting, "cmd :: bap_stop_in_starting <BdAddr> <profile> <direction> <context>", 0 },
    { "bap_update_stream", do_bap_update_stream, "cmd :: bap_update_stream <BdAddr> <profile> <direction> <new context>", 0 },
    /* last entry */
    {NULL, NULL, "", 0},
};


static int console_cmd_maxlen = 0;

static void *cmdjob_handler(void *param)
{
    char *job_cmd = (char*)param;

    bdt_log("cmdjob starting (%s)", job_cmd);

    process_cmd(job_cmd, 1);

    bdt_log("cmdjob terminating");

    free(job_cmd);
    return NULL;
}

static int create_cmdjob(char *cmd)
{
    pthread_t thread_id;
    char *job_cmd;

    job_cmd = (char*)calloc(1, strlen(cmd)+1); /* freed in job handler */
    if (job_cmd) {
       strlcpy(job_cmd, cmd,(strlen(cmd)+1));
       if (pthread_create(&thread_id, NULL, cmdjob_handler, (void *)job_cmd) != 0)
      /*if (pthread_create(&thread_id, NULL,
                       (void*)cmdjob_handler, (void*)job_cmd) !=0)*/
         perror("pthread_create");
      return 0;
    }
    else
       perror("create_Cmdjob malloc failed ");
    return -1;
}

/******************************************************************************
*
 ** Load stack lib

*******************************************************************************/
#define BLUETOOTH_LIBRARY_NAME "libbluetooth_qti.so"
int load_bt_lib(const bt_interface_t** interface) {
    const char* sym = BLUETOOTH_INTERFACE_STRING;
  bt_interface_t* itf = nullptr;

  // Always try to load the default Bluetooth stack on GN builds.
  const char* path = BLUETOOTH_LIBRARY_NAME;
  void* handle = dlopen(path, RTLD_NOW);
  if (!handle) {
    //const char* err_str = dlerror();
    printf("failed to load Bluetooth library\n");
    goto error;
  }

  // Get the address of the bt_interface_t.
  itf = (bt_interface_t*)dlsym(handle, sym);
  if (!itf) {
    printf("failed to load symbol from Bluetooth library\n");
    goto error;
  }

  // Success.
  printf(" loaded HAL Success\n");
  *interface = itf;
  return 0;

error:
  *interface = NULL;
  if (handle) dlclose(handle);

  return -EINVAL;
}

int HAL_load(void)
{
    if (load_bt_lib((bt_interface_t const**)&sBtInterface)) {
        printf("No Bluetooth Library found\n");
        return -1;
    }
    return 0;
}

int HAL_unload(void)
{
    int err = 0;

    bdt_log("Unloading HAL lib");

    sBtInterface = NULL;

    bdt_log("HAL library unloaded (%s)", strerror(err));

    return err;
}

/******************************************************************************
*
 ** HAL test functions & callbacks

*******************************************************************************/

void setup_test_env(void)
{
    int i = 0;

    while (console_cmd_list[i].name != NULL)
    {
        console_cmd_maxlen = MAX(console_cmd_maxlen, (int)strlen(console_cmd_list[i].name));
        i++;
    }
}

void check_return_status(int status)
{
    if (status != BT_STATUS_SUCCESS)
    {
        bdt_log("HAL REQUEST FAILED status : %d (%s)", status, dump_bt_status(status));
    }
    else
    {
        bdt_log("HAL REQUEST SUCCESS");
    }
}

static void do_set_localname(char *p)
{
    printf("set name in progress: %s\n", p);
    bt_property_t property = {BT_PROPERTY_BDNAME, static_cast<int>(strlen(p)), p};
    status =  sBtInterface->set_adapter_property(&property);
}

static void adapter_state_changed(bt_state_t state)
{
    int V1 = 1000, V2=2;
    char V3[] = "bap_uclient_test";
    bt_property_t property = {(bt_property_type_t)9 /*
BT_PROPERTY_DISCOVERY_TIMEOUT*/, 4, &V1};
    bt_property_t property1 = {(bt_property_type_t)7 /*SCAN*/, 2, &V2};
    bt_property_t property2 ={(bt_property_type_t)1,9, &V3};
    printf("ADAPTER STATE UPDATED : %s\n", (state == BT_STATE_OFF)?"OFF":"ON");

    g_AdapterState = state;

    if (state == BT_STATE_ON) {
        bt_enabled = 1;
        status = sBtInterface->set_adapter_property(&property1);
        status = sBtInterface->set_adapter_property(&property);
        status = sBtInterface->set_adapter_property(&property2);
    } else {
        bt_enabled = 0;
    }
}

static void adapter_properties_changed(bt_status_t status,
         int num_properties, bt_property_t *properties)
{
 char Bd_addr[15] = {0};
    if(NULL == properties)
    {
        printf("properties is null\n");
        return;
    }
    switch(properties->type)
    {
    case BT_PROPERTY_BDADDR:
        memcpy(Bd_addr, properties->val, properties->len);
        break;
    default:
        printf("property type not used\n");
    }
    return;
}

static void discovery_state_changed(bt_discovery_state_t state)
{
    printf("Discovery State Updated : %s\n",
         (state == BT_DISCOVERY_STOPPED)?"STOPPED":"STARTED");
}


static void pin_request_cb(RawAddress* remote_bd_addr, bt_bdname_t *bd_name,
      uint32_t cod, bool min_16_digit )
{
    remote_bd_address = remote_bd_addr;
    //bt_pin_code_t pincode = {{0x31, 0x32, 0x33, 0x34}};
    printf("Enter the pin key displayed in the remote device and terminate the key entry with .\n");

    /*if(BT_STATUS_SUCCESS != sBtInterface->pin_reply(remote_bd_addr, TRUE, 4
, &pincode))
    {
        printf("Pin Reply failed\n");
    }*/
}
static void ssp_request_cb(RawAddress* remote_bd_addr, bt_bdname_t *bd_name,
                           uint32_t cod, bt_ssp_variant_t pairing_variant,
uint32_t pass_key)
{
    printf("ssp_request_cb : name=%s variant=%d passkey=%u\n", bd_name->name,
pairing_variant, pass_key);
    if(BT_STATUS_SUCCESS != sBtInterface->ssp_reply(remote_bd_addr,
pairing_variant, TRUE, pass_key))
    {
        printf("SSP Reply failed\n");
    }
}

static void bond_state_changed_cb(bt_status_t status, RawAddress*
remote_bd_addr, bt_bond_state_t state)
{
    g_PairState = state;
}

static void acl_state_changed(bt_status_t status, RawAddress* remote_bd_addr,
bt_acl_state_t state,
                              bt_hci_error_code_t hci_reason)
{
    printf("acl_state_changed : remote_bd_addr=%02x:%02x:%02x:%02x:%02x:%02x, \
           acl status=%s \n",
    remote_bd_addr->address[0], remote_bd_addr->address[1], remote_bd_addr->address[2],
    remote_bd_addr->address[3], remote_bd_addr->address[4], remote_bd_addr->address[5],
    (state == BT_ACL_STATE_CONNECTED)?"ACL Connected" :"ACL Disconnected");
}
static void dut_mode_recv(uint16_t opcode, uint8_t *buf, uint8_t len)
{
    bdt_log("DUT MODE RECV : NOT IMPLEMENTED");
}

static void le_test_mode(bt_status_t status, uint16_t packet_count)
{
    bdt_log("LE TEST MODE END status:%s number_of_packets:%d",
         dump_bt_status(status), packet_count);
}

extern int timer_create (clockid_t, struct sigevent *__restrict, timer_t *
__restrict);
extern int timer_settime (timer_t, int, const struct itimerspec *__restrict,
struct itimerspec *__restrict);

static bool set_wake_alarm(uint64_t delay_millis, bool should_wake, alarm_cb
cb, void *data)
{

   static timer_t timer;
   static bool timer_created;

   if (!timer_created) {
      struct sigevent sigevent;
      memset(&sigevent, 0, sizeof(sigevent));
      sigevent.sigev_notify = SIGEV_THREAD;
      sigevent.sigev_notify_function = (void (*)(union sigval))cb;
      sigevent.sigev_value.sival_ptr = data;
      timer_create(CLOCK_MONOTONIC, &sigevent, &timer);
      timer_created = true;
   }

   struct itimerspec new_value;
   new_value.it_value.tv_sec = delay_millis / 1000;
   new_value.it_value.tv_nsec = (delay_millis % 1000) * 1000 * 1000;
   new_value.it_interval.tv_sec = 0;
   new_value.it_interval.tv_nsec = 0;
   timer_settime(timer, 0, &new_value, NULL);

  return TRUE;
}

static int acquire_wake_lock(const char *lock_name)
{
    return BT_STATUS_SUCCESS;
}

static int release_wake_lock(const char *lock_name)
{
    return BT_STATUS_SUCCESS;
}

static bt_callbacks_t bt_callbacks = {
    sizeof(bt_callbacks_t),
    adapter_state_changed,
    adapter_properties_changed, /*adapter_properties_cb */
    NULL, /* remote_device_properties_cb */
    NULL, /* device_found_cb */
    discovery_state_changed, /* discovery_state_changed_cb */
    pin_request_cb, /* pin_request_cb  */
    ssp_request_cb, /* ssp_request_cb  */
    bond_state_changed_cb, /*bond_state_changed_cb */
    acl_state_changed, /* acl_state_changed_cb */
    NULL, /* thread_evt_cb */
    dut_mode_recv, /*dut_mode_recv_cb */
    le_test_mode, /* le_test_mode_cb */
    NULL      /*energy_info_cb*/
};

static bt_os_callouts_t bt_os_callbacks = {
     sizeof(bt_os_callouts_t),
     set_wake_alarm,
     acquire_wake_lock,
     release_wake_lock
};


void bdt_enable(void)
{
    bdt_log("ENABLE BT");
    if (bt_enabled) {
        bdt_log("Bluetooth is already enabled");
        return;
    }
    status = sBtInterface->enable();

    check_return_status(status);
}

void bdt_disable(void)
{
    bdt_log("DISABLE BT");
    if (!bt_enabled) {
        bdt_log("Bluetooth is already disabled");
        return;
    }
    status = sBtInterface->disable();

    check_return_status(status);
}

void do_pairing(char *p)
{
    RawAddress bd_addr = {{0}};
    int transport = GATT_TRANSPORT_LE;
    if(FALSE == GetBdAddr(p, &bd_addr))    return;    // arg1
    if(BT_STATUS_SUCCESS != sBtInterface->create_bond(&bd_addr, transport))
    {
        printf("Failed to Initiate Pairing \n");
        return;
    }
}


void bdt_cleanup(void)
{
    bdt_log("CLEANUP");
    sBtInterface->cleanup();
}

/******************************************************************************
*
 ** Console commands

*******************************************************************************/

void do_help(char *p)
{
    int i = 0;
    char line[128];
//    int pos = 0;

    while (console_cmd_list[i].name != NULL)
    {
        snprintf(line, 128,"%s", (char*)console_cmd_list[i].name);
        bdt_log("%s %s\n", (char*)line, (char*)console_cmd_list[i].help);
        i++;
    }
}

void do_quit(char *p)
{
    bdt_shutdown();
}

/*******************************************************************
 *
 *  BT TEST  CONSOLE COMMANDS
 *
 *  Parses argument lists and passes to API test function
 *
*/

void do_init(char *p)
{
    bdt_init();
}

void do_enable(char *p)
{
    bdt_enable();
}

using bluetooth::bap::pacs::PacsClientInterface;
using bluetooth::bap::pacs::PacsClientCallbacks;

static PacsClientInterface* sPacsClientInterface = nullptr;
static uint16_t pacs_client_id = 0;
static uint8_t pacsSearchComplete = 0;
static uint8_t pacsConnectionComplete = 0;
static uint8_t bapConnectionComplete = 0;
static RawAddress pac_bd_addr;

class PacsClientCallbacksImpl : public PacsClientCallbacks {
 public:
  ~PacsClientCallbacksImpl() = default;
  void OnInitialized(int status,
                     int client_id) override {
    printf("%d\n", client_id);
    pacs_client_id = client_id;
  }
  void OnConnectionState(const RawAddress& bd_addr,
                         bluetooth::bap::pacs::ConnectionState state)
override {
    printf("%s\n", __func__);
    if(state == bluetooth::bap::pacs::ConnectionState::CONNECTED)  {
      printf("%s Connected\n", __func__);
      pacsConnectionComplete = 1;
    } else if(state == bluetooth::bap::pacs::ConnectionState::DISCONNECTED)  {
      printf("%s Disconnected\n", __func__);
    }
  }
  void OnAudioContextAvailable(const RawAddress& bd_addr,
                        uint32_t available_contexts) override {
    printf("%s\n", __func__);
  }
   void OnSearchComplete(int status, const RawAddress& address,
            std::vector<bluetooth::bap::pacs::CodecConfig> sink_pac_records,
            std::vector<bluetooth::bap::pacs::CodecConfig> src_pac_records,
            uint32_t sink_locations,
            uint32_t src_locations,
            uint32_t available_contexts,
            uint32_t supported_contexts) override {
    pacsSearchComplete = 1;
    printf("%s\n", __func__);
  }
};

static PacsClientCallbacksImpl sPacsClientCallbacks;

void do_pacs_discovery(char *p)
{
  if(FALSE == GetBdAddr(p, &pac_bd_addr))    return;    // arg1
  sPacsClientInterface = (PacsClientInterface*)
        sBtInterface->get_profile_interface(BT_PROFILE_PACS_CLIENT_ID);
  sPacsClientInterface->Init(&sPacsClientCallbacks);
  sleep(1);
  printf("%s going for connect\n", __func__);
  sPacsClientInterface->Connect(pacs_client_id, pac_bd_addr);
  while(!pacsConnectionComplete) sleep(1);
  printf("%s going for discovery\n", __func__);
  sPacsClientInterface->StartDiscovery(pacs_client_id, pac_bd_addr);
  while(!pacsSearchComplete) sleep(1);
  printf("%s going for disconnect\n", __func__);
  sleep(5);
  sPacsClientInterface->Disconnect(pacs_client_id, pac_bd_addr);
}

using bluetooth::bap::ascs::AscsClientInterface;
using bluetooth::bap::ascs::AscsClientCallbacks;

static AscsClientInterface* sAscsClientInterface = nullptr;
static uint16_t ascs_client_id = 0;
static uint8_t ascsSearchComplete = 0;
static uint8_t ascsConnectionComplete = 0;
static RawAddress ascs_bd_addr;

class AscsClientCallbacksImpl : public AscsClientCallbacks {
  public:
    ~AscsClientCallbacksImpl() = default;
    void OnAscsInitialized(int status, int client_id) override {
        printf("%d\n", client_id);
        ascs_client_id = client_id;
    }

    void OnConnectionState(const RawAddress& address,
                       bluetooth::bap::ascs::GattState state) override {
        printf("%s\n", __func__);
        if(state == bluetooth::bap::ascs::GattState::CONNECTED)  {
          printf("%s Connected\n", __func__);
          ascsConnectionComplete = 1;
        } else if(state == bluetooth::bap::ascs::GattState::DISCONNECTED)  {
          printf("%s Disconnected\n", __func__);
        }
    }

    void OnAseOpFailed(const RawAddress& address,
        bluetooth::bap::ascs::AseOpId ase_op_id,
        std::vector<bluetooth::bap::ascs::AseOpStatus> status) {
        printf("%s\n", __func__);

    }

    void OnAseState(const RawAddress& address,
                          bluetooth::bap::ascs::AseParams ase) override {
        printf("%s\n", __func__);
    }

    void OnSearchComplete(int status, const RawAddress& address,
        std::vector<bluetooth::bap::ascs::AseParams> sink_ase_list,
        std::vector<bluetooth::bap::ascs::AseParams> src_ase_list) override {
        printf("%s\n", __func__);
        ascsSearchComplete = 1;
    }
};

static AscsClientCallbacksImpl sAscsClientCallbacks;

void do_ascs_discovery(char *p)
{
  if(FALSE == GetBdAddr(p, &ascs_bd_addr))    return;    // arg1
  sAscsClientInterface = (AscsClientInterface*)
        sBtInterface->get_profile_interface(BT_PROFILE_ASCS_CLIENT_ID);
  sAscsClientInterface->Init(&sAscsClientCallbacks);
  sleep(1);
  printf("%s going for connect\n", __func__);
  sAscsClientInterface->Connect(ascs_client_id, ascs_bd_addr);
  while(!ascsConnectionComplete) sleep(1);
  printf("%s going for discovery\n", __func__);
  sAscsClientInterface->StartDiscovery(ascs_client_id, ascs_bd_addr);
  while(!ascsSearchComplete) sleep(1);
  printf("%s going for disconnect\n", __func__);
  sAscsClientInterface->Disconnect(ascs_client_id, ascs_bd_addr);
}

template <typename T>
std::string loghex(T x) {
   std::stringstream tmp;
   tmp << "0x" << std::internal << std::hex << std::setfill('0')
       << std::setw(sizeof(T) * 2) << (unsigned int)x;
   return tmp.str();
}

using bluetooth::bap::ucast::UcastClientCallbacks;
using bluetooth::bap::ucast::UcastClientInterface;

static UcastClientInterface* sUcastClientInterface = nullptr;

class UcastClientCallbacksImpl : public UcastClientCallbacks {
 public:
  ~UcastClientCallbacksImpl() = default;
  void OnStreamState(const RawAddress &address,
      std::vector<bluetooth::bap::ucast::StreamStateInfo> streams_state_info) override {
    for (auto it = streams_state_info.begin();
                         it != streams_state_info.end(); it++) {
      printf("%s stream type %d\n", __func__, (it->stream_type.type));
      printf("%s stream dir %s\n", __func__, loghex(it->stream_type.direction).c_str());
      printf("%s stream state %d\n", __func__, static_cast<int> (it->stream_state));
      if(static_cast<int> (it->stream_state) == 2 ||
         static_cast<int> (it->stream_state) == 0) {
        bapConnectionComplete = 1;
      }
    }
  }
  void OnStreamConfig(const RawAddress &address,
      std::vector<bluetooth::bap::ucast::StreamConfigInfo> streams_config_info) override {
    printf("%s\n",__func__);
  }
  void OnStreamAvailable(const RawAddress &address,
                      uint16_t src_audio_contexts,
                      uint16_t sink_audio_contexts)  override {
    printf("%s\n",__func__);
  }
};

static UcastClientCallbacksImpl sUcastClientCallbacks;

typedef struct {
    char bdAddr[13];
    uint16_t profile;
    uint16_t context;
    uint8_t direction;
} Servers;

typedef struct {
    uint8_t cnt;
    char codecConfig[7];
    char audioConfig[5];
    std::vector<Servers> serv;
} UserParms;

typedef struct {
    uint8_t audio_dir;
    uint8_t stereo;
} AudioType;

typedef struct {
    uint8_t num_servers;
    uint8_t num_cises;
    std::vector<AudioType> audio_type;
} AudioConfigSettings;

//

std::map<std::string, AudioConfigSettings> audioConfigMap = {
 {"1_1", {1, 1, {{ASE_DIRECTION_SINK, 0}}}},  // EB streaming
 {"2_1", {1, 1, {{ASE_DIRECTION_SRC, 0}}}},   // EB Recording
 {"3_1", {1, 1, {{ASE_DIRECTION_SRC|ASE_DIRECTION_SINK, 0}}}}, // EB Call Mono Bi-Dir CIS
 {"4_1", {1, 1, {{ASE_DIRECTION_SINK, ASE_SINK_STEREO}}}}, // Stereo Headset stereo streaming

 {"5_1", {1, 1, {{ASE_DIRECTION_SRC|ASE_DIRECTION_SINK, ASE_SINK_STEREO}}}}, // EB Call with speaker stereo  mono mic

 {"6_1", {1, 2, {{ASE_DIRECTION_SINK, 0}, {ASE_DIRECTION_SINK, 0}}}}, // TWM Streaming
 {"6_2", {2, 2, {{ASE_DIRECTION_SINK, 0}, {ASE_DIRECTION_SINK, 0}}}}, // EBP Streaming same as 1_1
 {"7_1", {1, 2, {{ASE_DIRECTION_SINK, 0}, {ASE_DIRECTION_SRC, 0}}}},  // EB Call with dual CIS ( same as 3_1)
 {"7_2", {2, 2, {{ASE_DIRECTION_SINK, 0}, {ASE_DIRECTION_SRC, 0}}}},  // EBP Call with speaker on EB1 and mic on EB2
 {"8_1", {1, 2, {{ASE_DIRECTION_SINK, 0}, {ASE_DIRECTION_SRC|ASE_DIRECTION_SINK, 0}}}}, // Headset Call with single mic
 {"8_2", {2, 2, {{ASE_DIRECTION_SRC|ASE_DIRECTION_SINK, 0}, {ASE_DIRECTION_SINK, 0}}}}, // EBP Call with mic from one EB
 {"9_1", {1, 2, {{ASE_DIRECTION_SRC, 0}, {ASE_DIRECTION_SRC, 0}}}}, // TWM Recording
 {"9_2", {2, 2, {{ASE_DIRECTION_SRC, 0}, {ASE_DIRECTION_SRC, 0}}}}, // EBP Recording
{"10_1", {1, 1, {{ASE_DIRECTION_SRC, ASE_SRC_STEREO}}}}, // EB stereo Recording
{"11_1", {1, 2, {{ASE_DIRECTION_SRC|ASE_DIRECTION_SINK, 0}, {ASE_DIRECTION_SRC|ASE_DIRECTION_SINK, 0}}}}, // TWM Call
{"11_2", {2, 2, {{ASE_DIRECTION_SRC|ASE_DIRECTION_SINK, 0}, {ASE_DIRECTION_SRC|ASE_DIRECTION_SINK, 0}}}}}; // EBP Call

int getInt(std::string &str)
{
    int ret;
    std::stringstream integer(str);
    integer >> ret;
    return ret;
}

void parse_parms(char *p, UserParms *ptr)
{
    std::string line(p);
    std::vector <std::string> token;
    std::stringstream check1(line);
    std::string intermediate;
    while(getline(check1, intermediate, ' '))
    {
        token.push_back(intermediate);
    }
    ptr->cnt = token.size();
    if (ptr->cnt == 11)
    {
        memcpy(ptr->codecConfig, token[1].c_str(), token[1].size());
        memcpy(ptr->audioConfig, token[2].c_str(), token[2].size());
        Servers serv1, serv2;
        memcpy(serv1.bdAddr, token[3].c_str(), token[3].size());
        serv1.profile = static_cast<uint16_t>(getInt(token[4]));
        serv1.direction = static_cast<uint16_t>(getInt(token[5]));
        serv1.context = static_cast<uint16_t>(getInt(token[6]));
        ptr->serv.push_back(serv1);
        memcpy(serv2.bdAddr, token[7].c_str(), token[7].size());
        serv2.profile = static_cast<uint16_t>(getInt(token[8]));
        serv2.direction = static_cast<uint16_t>(getInt(token[9]));
        serv2.context = static_cast<uint16_t>(getInt(token[10]));
        ptr->serv.push_back(serv2);
    }
    else if (ptr->cnt == 9)
    {
        Servers serv1, serv2;
        memcpy(serv1.bdAddr, token[1].c_str(), token[1].size());
        serv1.profile = static_cast<uint16_t>(getInt(token[2]));
        serv1.direction = static_cast<uint16_t>(getInt(token[3]));
        serv1.context = static_cast<uint16_t>(getInt(token[4]));
        ptr->serv.push_back(serv1);
        memcpy(serv2.bdAddr, token[5].c_str(), token[5].size());
        serv2.profile = static_cast<uint16_t>(getInt(token[6]));
        serv2.direction = static_cast<uint16_t>(getInt(token[7]));
        serv2.context = static_cast<uint16_t>(getInt(token[8]));
        ptr->serv.push_back(serv2);
    }
    else if (ptr->cnt == 7)
    {
        memcpy(ptr->codecConfig, token[1].c_str(), token[1].size());
        memcpy(ptr->audioConfig, token[2].c_str(), token[2].size());
        Servers serv1;
        memcpy(serv1.bdAddr, token[3].c_str(), token[3].size());
        serv1.profile = static_cast<uint16_t>(getInt(token[4]));
        serv1.direction = static_cast<uint16_t>(getInt(token[5]));
        serv1.context = static_cast<uint16_t>(getInt(token[6]));
        ptr->serv.push_back(serv1);
    }
    else if (ptr->cnt == 5)
    {
        Servers serv1;
        memcpy(serv1.bdAddr, token[1].c_str(), token[1].size());
        serv1.profile = static_cast<uint16_t>(getInt(token[2]));
        serv1.direction = static_cast<uint16_t>(getInt(token[3]));
        serv1.context = static_cast<uint16_t>(getInt(token[4]));
        ptr->serv.push_back(serv1);
    }
    else
    {
        printf("%s ERROR: Input\n", __func__);
    }
}

constexpr uint8_t  CONFIG_FRAME_DUR_INDEX       = 0x04;
constexpr uint8_t  CONFIG_OCTS_PER_FRAME_INDEX  = 0x04;
constexpr uint8_t  CONFIG_PREF_AUDIO_CONT_INDEX = 0x06; // CS1

bool UpdateFrameDuration(bluetooth::bap::pacs::CodecConfig *config ,
         uint8_t frame_dur) {
   uint64_t value = 0xFF;
   config->codec_specific_1 &=
       ~(value << (CONFIG_FRAME_DUR_INDEX*8));
   config->codec_specific_1 |=
       static_cast<uint64_t>(frame_dur) << (CONFIG_FRAME_DUR_INDEX * 8);
   return true;
}


bool UpdatePreferredAudioContext(bluetooth::bap::pacs::CodecConfig *config ,
                                    uint16_t pref_audio_context) {
  uint64_t value = 0xFFFF;
  config->codec_specific_1 &= ~(value << (CONFIG_PREF_AUDIO_CONT_INDEX*8));
  config->codec_specific_1 |=  static_cast<uint64_t>(pref_audio_context) <<
                               (CONFIG_PREF_AUDIO_CONT_INDEX * 8);
  return true;
}

bool UpdateOctsPerFrame(bluetooth::bap::pacs::CodecConfig *config ,
        uint16_t octs_per_frame) {
    uint64_t value = 0xFFFF;
    config->codec_specific_2 &=
        ~(value << (CONFIG_OCTS_PER_FRAME_INDEX * 8));
    config->codec_specific_2 |=
        static_cast<uint64_t>(octs_per_frame) << (CONFIG_OCTS_PER_FRAME_INDEX * 8);
    return true;
}

void set_conn_info(bluetooth::bap::ucast::StreamConnect *conn_info, int type, int context, int dir)
{
    conn_info->stream_type.type = type;
    conn_info->stream_type.direction = dir;
    conn_info->stream_type.audio_context = context;
}

bluetooth::bap::pacs::CodecSampleRate get_sample_rate (char *p)
{
    std::string str = p;
    if (str.find("16_") != std::string::npos)
        return bluetooth::bap::pacs::CodecSampleRate::CODEC_SAMPLE_RATE_16000;
    else if (str.find("24_") != std::string::npos)
        return bluetooth::bap::pacs::CodecSampleRate::CODEC_SAMPLE_RATE_24000;
    else if (str.find("32_") != std::string::npos)
        return bluetooth::bap::pacs::CodecSampleRate::CODEC_SAMPLE_RATE_32000;
    else if (str.find("48_") != std::string::npos)
        return bluetooth::bap::pacs::CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    else if (str.find("8_") != std::string::npos)
        return bluetooth::bap::pacs::CodecSampleRate::CODEC_SAMPLE_RATE_8000;
    else
        return bluetooth::bap::pacs::CodecSampleRate::CODEC_SAMPLE_RATE_NONE;
}

int get_frame_duration (char *p)
{
    std::string str = p;
    int ret;
    if ((str.find("_1_") != std::string::npos) ||
        (str.find("_3_") != std::string::npos) ||
        (str.find("_5_") != std::string::npos))
        ret = static_cast<int>(bluetooth::bap::pacs::CodecFrameDuration::FRAME_DUR_7_5);
    else if ((str.find("_2_") != std::string::npos) ||
             (str.find("_4_") != std::string::npos) ||
             (str.find("_6_") != std::string::npos))
        ret = static_cast<int>(bluetooth::bap::pacs::CodecFrameDuration::FRAME_DUR_10);
    else
        ret = -1;
    return ret;
}

int get_sdu_interval (char *p)
{
    std::string str = p;
    int ret;
    if ((str.find("_1_") != std::string::npos) ||
        (str.find("_3_") != std::string::npos) ||
        (str.find("_5_") != std::string::npos))
        ret = 7500;
    else if ((str.find("_2_") != std::string::npos) ||
             (str.find("_4_") != std::string::npos) ||
             (str.find("_6_") != std::string::npos))
        ret = 10000;
    else
        ret = -1;
    return ret;
}

std::map<std::string, int> octetPerFrame =
{{"8_1", 26},{"8_2", 30},{"16_1", 30},{"16_2", 40},
{"24_1", 45},{"24_2", 60},{"32_1", 60},{"32_2", 80},
{"48_1", 75},{"48_2", 100},{"48_3", 90},{"48_4", 120},
{"48_5", 117},{"48_6", 155}};

int get_octetPerFrame (char *p)
{
    std::string str = p;
    int ret = -1;
    size_t pos = str.rfind('_');
    std::string key = str.substr(0, pos);
    for (std::map<std::string, int>::iterator it =
        octetPerFrame.begin(); it != octetPerFrame.end(); it++)
    {
        if (key.compare(it->first) == 0)
            ret = it->second;
    }
    return ret;
}

std::map<std::string, int> tport_latency =
{{"8_1_1", 8},{"16_1_1", 8},{"24_1_1", 8},{"32_1_1", 8},
 {"8_2_1", 10},{"16_2_1", 10},{"24_2_1", 10},{"32_2_1", 10},
{"48_1_1", 15},{"48_3_1", 15},{"48_5_1", 15},
{"48_2_1", 20},{"48_4_1", 20},{"48_6_1", 20},
 {"8_1_2", 75},{"16_1_2", 75},{"24_1_2", 75},
{"31_1_2", 75},{"48_1_2", 75},{"48_3_2", 75},{"48_5_2", 75},
 {"8_2_2", 95},{"16_2_2", 95},{"24_2_2", 95},
{"32_2_2", 95},{"48_2_2", 95},
{"48_4_2", 100},{"48_6_2", 100}};

int get_tport_latency (char *p)
{
    std::string str = p;
    for (std::map<std::string, int>::iterator it = tport_latency.begin();
        it != tport_latency.end(); it++)
    {
        if (str.compare(it->first) == 0)
            return it->second;
    }
    return -1;
}

int get_rtn (char *p)
{
    std::string str = p;
    int ret;
    size_t pos = str.rfind('_');
    std::string key = str.substr(pos);
    if (str.find("_1_2") != std::string::npos ||
        str.find("_2_2") != std::string::npos ||
        str.find("_3_2") != std::string::npos ||
        str.find("_4_2") != std::string::npos ||
        str.find("_5_2") != std::string::npos ||
        str.find("_6_2") != std::string::npos ) {
        ret = 13;
        return ret;
    }
    if (str.find("48_") != std::string::npos)
        ret = 5;
    if ((str.find("8_") != std::string::npos) ||
        (str.find("16_") != std::string::npos) ||
        (str.find("24_") != std::string::npos) ||
        (str.find("32_") != std::string::npos))
        ret = 2;
    else
        ret = -1;
    return ret;
}

int getAudioConfigSettings(char *p, AudioConfigSettings *ptr)
{
    int ret = -1;
    std::string key = p;
    for (std::map<std::string, AudioConfigSettings>::iterator it =
        audioConfigMap.begin();
        it != audioConfigMap.end(); it++)
    {
        if (key.compare(it->first) == 0)
        {
            *ptr = it->second;
            printf(" %s ERROR: audio type 0 %d \n", __func__, ptr->audio_type[0].audio_dir);
            printf(" %s ERROR: audio type 1 %d \n", __func__, ptr->audio_type[1].audio_dir);
            //memcpy(ptr, &it->second, sizeof(AudioConfigSettings));
            ret = 0;
        }
    }
    return ret;
}

typedef struct
{
    uint8_t A;
    uint8_t B;
    uint8_t C;
} setFormat;

void set(void *dest, setFormat src)
{
    memcpy(dest, &src, sizeof(setFormat));
}

void set_codec_qos_config (bluetooth::bap::ucast::CodecQosConfig *codec_qos_config,
                           char *codecConfig, AudioConfigSettings *acs,
                           uint8_t audio_direction, uint16_t context,
                           uint8_t server_id,
                           uint8_t server_count, uint8_t total_servers)
{
    int frameDuration, octetPerFrame, tport_latency, sdu_interval, rtn, cis_t;
    bluetooth::bap::pacs::CodecSampleRate sampleRate;
    bool stereo_t = false;
    bluetooth::bap::ucast::CIGConfig cig_config;
    sampleRate = get_sample_rate(codecConfig);
    printf("Sample Rate %d\n", sampleRate);
    printf("server_id  %d\n", server_id);

    if (sampleRate == bluetooth::bap::pacs::CodecSampleRate::CODEC_SAMPLE_RATE_NONE)
    {
        printf(" %s ERROR: sample rate\n", __func__);
        exit(0);
    }
    frameDuration = get_frame_duration(codecConfig);
    if (frameDuration < 0)
    {
        printf(" %s ERROR: frame duration\n", __func__);
        exit(0);
    }
    octetPerFrame = get_octetPerFrame(codecConfig);
    if (octetPerFrame < 0)
    {
        printf(" %s ERROR: octet per frame\n", __func__);
        exit(0);
    }
    tport_latency = get_tport_latency(codecConfig);
    if (tport_latency < 0)
    {
        printf(" %s ERROR: max transport latency\n", __func__);
        exit(0);
    }
    rtn = get_rtn(codecConfig);
    if (rtn < 0)
    {
        printf(" %s ERROR: re-transmission\n", __func__);
        exit(0);
    }
    sdu_interval = get_sdu_interval(codecConfig);
    codec_qos_config->codec_config.codec_type =
        bluetooth::bap::pacs::CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config->codec_config.codec_priority =
        bluetooth::bap::pacs::CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config->codec_config.sample_rate = sampleRate;
    UpdateFrameDuration(&codec_qos_config->codec_config,
        static_cast<uint8_t>(frameDuration));
    UpdatePreferredAudioContext(&codec_qos_config->codec_config, context);
    cig_config.cig_id = 1;
    cig_config.cis_count = acs->num_cises;
    cig_config.packing = 0x01; // interleaved
    cig_config.framing = 0x00; // unframed
    cig_config.max_tport_latency_m_to_s = static_cast<uint16_t>(tport_latency);
    cig_config.max_tport_latency_s_to_m = static_cast<uint16_t>(tport_latency);
    if (sdu_interval == 7500)
    {
        set(&cig_config.sdu_interval_m_to_s, {0x4C, 0x1D, 0x00});
        set(&cig_config.sdu_interval_s_to_m, {0x4C, 0x1D, 0x00});
    }
    else
    {
        set(&cig_config.sdu_interval_m_to_s, {0x10, 0x27, 0x00});
        set(&cig_config.sdu_interval_s_to_m, {0x10, 0x27, 0x00});
    }
    memcpy(&codec_qos_config->qos_config.cig_config,
        &cig_config, sizeof(cig_config));
    for (uint8_t i = 0; i < acs->num_cises; i++) {
        bluetooth::bap::ucast::CISConfig cis_config;
        bluetooth::bap::ucast::ASCSConfig ascs_config;
        int max_sdu_m_to_s;
        int max_sdu_s_to_m;
        cis_config.cis_id = i;
        ascs_config.cig_id = 1;
        ascs_config.cis_id = i;
        max_sdu_m_to_s = max_sdu_s_to_m = get_octetPerFrame(codecConfig);
        printf("audio_dir %d\n", acs->audio_type[i].audio_dir);
        printf("max_sdu_m_to_s %d\n", max_sdu_m_to_s);
        printf("max_sdu_s_to_m %d\n", max_sdu_s_to_m);
        if(acs->audio_type[i].stereo & ASE_SRC_STEREO) {
          max_sdu_s_to_m *= 2;
          if(audio_direction & ASE_DIRECTION_SRC) stereo_t = true;
        }
        if(acs->audio_type[i].stereo & ASE_SINK_STEREO) {
          max_sdu_m_to_s *= 2;
          if(audio_direction & ASE_DIRECTION_SINK) stereo_t = true;
        }

        if (acs->audio_type[i].audio_dir == (ASE_DIRECTION_SINK|ASE_DIRECTION_SRC))
        {
            printf("i %d   Filling both m to s and s to m \n", i);
            cis_config.max_sdu_m_to_s = static_cast<uint16_t>(max_sdu_m_to_s);
            cis_config.max_sdu_s_to_m = static_cast<uint16_t>(max_sdu_s_to_m);
            ascs_config.bi_directional = true;
        }
        else if (acs->audio_type[i].audio_dir == ASE_DIRECTION_SRC)
        {
            printf("i %d   Filling s to m \n", i);
            cis_config.max_sdu_s_to_m = static_cast<uint16_t>(max_sdu_s_to_m);
            cis_config.max_sdu_m_to_s = 0;
            ascs_config.bi_directional = false;
        }
        else if (acs->audio_type[i].audio_dir == ASE_DIRECTION_SINK)
        {
            printf("i %d   Filling m to s  \n", i);
            cis_config.max_sdu_m_to_s = static_cast<uint16_t>(max_sdu_m_to_s);
            cis_config.max_sdu_s_to_m = 0;
            ascs_config.bi_directional = false;
        }
        cis_config.phy_m_to_s = 0x02;
        cis_config.phy_s_to_m = 0x02;
        cis_config.rtn_m_to_s = static_cast<uint8_t>(rtn);
        cis_config.rtn_s_to_m = static_cast<uint8_t>(rtn);
        printf("rtn   %d   \n", rtn);
        set(&ascs_config.presentation_delay, {0x40, 0x9C, 0x00});
        codec_qos_config->qos_config.cis_configs.push_back(cis_config);


        printf("i %d   server_id   %d \n", i, server_id);
        if(total_servers == 1) {
          if(acs->num_cises == 1) {
            codec_qos_config->qos_config.ascs_configs.push_back(ascs_config);
          } else if(acs->num_cises == 2) {
            if(acs->audio_type[i % acs->num_cises].audio_dir ==
              acs->audio_type[(i + 1) % acs->num_cises].audio_dir) {
              codec_qos_config->qos_config.ascs_configs.push_back(ascs_config);
            } else if( i == server_count) {
              codec_qos_config->qos_config.ascs_configs.push_back(ascs_config);
            }
          }
        } else if(total_servers == 2) {
           if(i == server_id) {
             codec_qos_config->qos_config.ascs_configs.push_back(ascs_config);
           }
        }
    }
    if (stereo_t == true) {
        codec_qos_config->codec_config.channel_mode =
            bluetooth::bap::pacs::CodecChannelMode::CODEC_CHANNEL_MODE_STEREO;
        UpdateOctsPerFrame(&codec_qos_config->codec_config,
            static_cast<uint16_t>(octetPerFrame*2));
    } else {
        codec_qos_config->codec_config.channel_mode =
            bluetooth::bap::pacs::CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
        UpdateOctsPerFrame(&codec_qos_config->codec_config,
            static_cast<uint16_t>(octetPerFrame));
    }
}

void do_bap_connect (char *p)
{
    UserParms args;
    parse_parms(p, &args);
    bluetooth::bap::ucast::CodecQosConfig codec_qos_config;
    bluetooth::bap::ucast::CodecQosConfig codec_qos_config_2;
    AudioConfigSettings acs;
    bapConnectionComplete = 0;
    if (getAudioConfigSettings(args.audioConfig, &acs) < 0)
    {
        printf("%s ERROR: AudioConfig\n", __func__);
        exit(0);
    }
    //set_codec_qos_config(&codec_qos_config, args.codecConfig, &acs);
    for (uint8_t i = 0; i < args.serv.size(); i++) {
        RawAddress bap_bd_addr;
        bluetooth::bap::ucast::StreamConnect conn_info;
        std::vector<bluetooth::bap::ucast::StreamConnect> streams;
        codec_qos_config.qos_config.cis_configs.clear();
        codec_qos_config.qos_config.ascs_configs.clear();
        codec_qos_config_2.qos_config.cis_configs.clear();
        codec_qos_config_2.qos_config.ascs_configs.clear();
        if(FALSE == GetBdAddr(args.serv[i].bdAddr, &bap_bd_addr))     return;
        if (args.serv[i].direction & ASE_DIRECTION_SINK)
        {
            set_codec_qos_config(&codec_qos_config, args.codecConfig,
                                 &acs, ASE_DIRECTION_SINK, args.serv[i].context,
                                 i, 0,
                                 args.serv.size());
            set_conn_info(&conn_info, args.serv[i].profile,
                args.serv[i].context, ASE_DIRECTION_SINK);
            printf("%s ERROR: context %d\n", __func__, args.serv[i].context);
            conn_info.codec_qos_config_pair.push_back(codec_qos_config);
            streams.push_back(conn_info);
        }
        if (args.serv[i].direction & ASE_DIRECTION_SRC)
        {
            set_codec_qos_config(&codec_qos_config_2, args.codecConfig,
                                 &acs, ASE_DIRECTION_SRC, args.serv[i].context,
                                 i, 1,
                                 args.serv.size());
            set_conn_info(&conn_info, args.serv[i].profile,
                args.serv[i].context, ASE_DIRECTION_SRC);
            printf("%s ERROR: context %d\n", __func__, args.serv[i].context);
            conn_info.codec_qos_config_pair.push_back(codec_qos_config_2);
            streams.push_back(conn_info);
        }
        std::vector<RawAddress> address;
        address.push_back(bap_bd_addr);
        sUcastClientInterface->Connect(address, true, streams);
    }
    while(!bapConnectionComplete) sleep(1);
}

void do_bap_disconnect (char *p)
{
    UserParms args;
    parse_parms(p, &args);
    for (uint8_t i = 0; i < ((args.cnt)/4); i++) {
        RawAddress bap_bd_addr;
        if(FALSE == GetBdAddr(args.serv[i].bdAddr, &bap_bd_addr)) return;
        std::vector<bluetooth::bap::ucast::StreamType> streams;
        if (args.serv[i].direction & 1) {
            bluetooth::bap::ucast::StreamType type_1 =
                      { .type = static_cast<uint8_t>(args.serv[i].profile),
                        .audio_context = args.serv[i].context,
                        .direction = 1
                      };
            streams.push_back(type_1);
        }
        if (args.serv[i].direction & 2) {
                    bluetooth::bap::ucast::StreamType type_1 =
                      { .type = static_cast<uint8_t>(args.serv[i].profile),
                        .audio_context = args.serv[i].context,
                        .direction = 2
                      };
            streams.push_back(type_1);
        }
        sUcastClientInterface->Disconnect(bap_bd_addr, streams);
    }
}

void do_bap_start (char *p)
{
    UserParms args;
    parse_parms(p, &args);
    for (uint8_t i = 0; i < ((args.cnt)/4); i++) {
        RawAddress bap_bd_addr;
        if(FALSE == GetBdAddr(args.serv[i].bdAddr, &bap_bd_addr)) return;
        std::vector<bluetooth::bap::ucast::StreamType> streams;
        if (args.serv[i].direction & 1) {
            bluetooth::bap::ucast::StreamType type_1 =
                      { .type = static_cast<uint8_t>(args.serv[i].profile),
                        .audio_context = args.serv[i].context,
                        .direction = 1
                      };
            streams.push_back(type_1);
        }
        if (args.serv[i].direction & 2) {
                    bluetooth::bap::ucast::StreamType type_1 =
                      { .type = static_cast<uint8_t>(args.serv[i].profile),
                        .audio_context = args.serv[i].context,
                        .direction = 2
                      };
            streams.push_back(type_1);
        }
        sUcastClientInterface->Start(bap_bd_addr, streams);
    }
}

void do_bap_stop (char *p)
{
    UserParms args;
    parse_parms(p, &args);
    for (uint8_t i = 0; i < ((args.cnt)/4); i++) {
        RawAddress bap_bd_addr;
        if(FALSE == GetBdAddr(args.serv[i].bdAddr, &bap_bd_addr)) return;
        std::vector<bluetooth::bap::ucast::StreamType> streams;
        if (args.serv[i].direction & 1) {
            bluetooth::bap::ucast::StreamType type_1 =
                      { .type = static_cast<uint8_t>(args.serv[i].profile),
                        .audio_context = args.serv[i].context,
                        .direction = 1
                      };
            streams.push_back(type_1);
        }
        if (args.serv[i].direction & 2) {
                    bluetooth::bap::ucast::StreamType type_1 =
                      { .type = static_cast<uint8_t>(args.serv[i].profile),
                        .audio_context = args.serv[i].context,
                        .direction = 2
                      };
            streams.push_back(type_1);
        }
        sUcastClientInterface->Stop(bap_bd_addr, streams);
    }
}

void do_bap_disc_in_connecting (char *p)
{
    int del;
    printf("Enter the delay (ms)> ");
    std::cin >> del;
    do_bap_connect(p);
    usleep(del *1000);
    do_bap_disconnect(p);
}

void do_bap_disc_in_starting (char *p)
{
    int del;
    printf("Enter the delay (ms)> ");
    std::cin >> del;
    do_bap_start(p);
    usleep(del *1000);
    do_bap_disconnect(p);
}

void do_bap_disc_in_stopping (char *p)
{
    int del;
    printf("Enter the delay (ms)> ");
    std::cin >> del;
    do_bap_stop(p);
    usleep(del *1000);
    do_bap_disconnect(p);
}

void do_bap_stop_in_starting (char *p)
{
    int del;
    printf("Enter the delay (ms)> ");
    std::cin >> del;
    do_bap_start(p);
    usleep(del *1000);
    do_bap_stop(p);
}

void do_bap_update_stream (char *p)
{
    UserParms args;
    parse_parms(p, &args);
    for (uint8_t i = 0; i < ((args.cnt)/4); i++) {
        RawAddress bap_bd_addr;
        if(FALSE == GetBdAddr(args.serv[i].bdAddr, &bap_bd_addr)) return;
        std::vector<bluetooth::bap::ucast::StreamUpdate> Update_Stream;
        if (args.serv[i].direction & 1) {
            bluetooth::bap::ucast::StreamType type_1 =
                      { .type = static_cast<uint8_t>(args.serv[i].profile),
                        .direction = 1
                      };
            bluetooth::bap::ucast::StreamUpdate sUpdate =
                      {
                        type_1,
                        bluetooth::bap::ucast::StreamUpdateType::STREAMING_CONTEXT,
                        args.serv[i].context
                      };
            Update_Stream.push_back(sUpdate);
        }
        if (args.serv[i].direction & 2) {
            bluetooth::bap::ucast::StreamType type_1 =
                      { .type = static_cast<uint8_t>(args.serv[i].profile),
                        .direction = 2
                      };
            bluetooth::bap::ucast::StreamUpdate sUpdate =
                      {
                        type_1,
                        bluetooth::bap::ucast::StreamUpdateType::STREAMING_CONTEXT,
                        args.serv[i].context
                      };
            Update_Stream.push_back(sUpdate);
        }
        sUcastClientInterface->UpdateStream(bap_bd_addr, Update_Stream);
    }
}

void do_disable(char *p)
{
    bdt_disable();
}

void do_cleanup(char *p)
{
    bdt_cleanup();
}

void bdt_init(void)
{
    bdt_log("INIT BT ");
    status = sBtInterface->init(&bt_callbacks, false, false, 0, nullptr, false);
    sleep(1);
    if (status == BT_STATUS_SUCCESS) {
        status = sBtInterface->set_os_callouts(&bt_os_callbacks);
    }
    check_return_status(status);
}

/******************************************************************************
*
 ** GATT SERVER API commands

*******************************************************************************/

/*
 * Main console command handler
*/

static void process_cmd(char *p, unsigned char is_job)
{
    char cmd[2048];
    int i = 0;
    bt_pin_code_t pincode;
    char *p_saved = p;

    get_str(&p, cmd);

    /* table commands */
    while (console_cmd_list[i].name != NULL)
    {
        if (is_cmd(console_cmd_list[i].name))
        {
            if (!is_job && console_cmd_list[i].is_job)
                create_cmdjob(p_saved);
            else
            {
                console_cmd_list[i].handler(p);
            }
            return;
        }
        i++;
    }
    //pin key
    if(cmd[6] == '.') {
        for(i=0; i<6; i++) {
            pincode.pin[i] = cmd[i];
        }
        if(BT_STATUS_SUCCESS != sBtInterface->pin_reply(remote_bd_address,
TRUE, strlen((const char*)pincode.pin), &pincode)) {
            printf("Pin Reply failed\n");
        }
        //flush the char for pinkey
        cmd[6] = 0;
    }
    else {
        bdt_log("%s : unknown command\n", p_saved);
        do_help(NULL);
    }
}

int main()
{
    config_permissions();
    bdt_log("\n:::::::::::::::::::::::::::::::::::::::::::::::::::");
    bdt_log(":: Bluedroid test app starting");

    if ( HAL_load() < 0 ) {
        perror("HAL failed to initialize, exit\n");
        unlink(PID_FILE);
        exit(0);
    }

    setup_test_env();

    /* Automatically perform the init */
    bdt_init();
    sleep(5);
    bdt_enable();
    sleep(5);

    sUcastClientInterface = (UcastClientInterface*)
        sBtInterface->get_profile_interface(BT_PROFILE_BAP_UCLIENT_ID);
    sUcastClientInterface->Init(&sUcastClientCallbacks);
    sPacsClientInterface = (PacsClientInterface*)
        sBtInterface->get_profile_interface(BT_PROFILE_PACS_CLIENT_ID);
    sPacsClientInterface->Init(&sPacsClientCallbacks);
    sAscsClientInterface = (AscsClientInterface*)
        sBtInterface->get_profile_interface(BT_PROFILE_ASCS_CLIENT_ID);
    sAscsClientInterface->Init(&sAscsClientCallbacks);

    sleep(5);
    while(!main_done)
    {
        char line[2048], *result;


        /* command prompt */
        printf( ">" );
        fflush(stdout);

        if ((result = fgets (line, 2048, stdin)) == NULL)
        {
            printf("ERROR: The string is NULL. code %d\n", errno);
            exit(0);
        }
        else
        {
            printf("UserInput\n");
        }

        if (line[0]!= '\0')
        {
            /* remove linefeed */
            line[strlen(line)-1] = 0;

            process_cmd(line, 0);
            memset(line, '\0', 2048);
        }
    }
    HAL_unload();

    bdt_log(":: bap uca test app terminating");

    return 0;
}

int GetFileName(char *p, char *filename)
{
//    uint8_t  i;
    int len;

    skip_blanks(&p);

    printf("Input file name = %s\n", p);

    if (p == NULL)
    {
        printf("\nInvalid File Name... Please enter file name\n");
        return FALSE;
    }
    len = strlen(p);

    memcpy(filename, p, len);
    filename[len] = '\0';

    return TRUE;
}
uint8_t check_length(char *p)
{
    uint8_t val = 0;
    while (*p != ' ' && *p != '\0')
    {
        val++;
        p++;
    }
    return val;
}
int GetBdAddr(char *p, RawAddress* pbd_addr)
{
    char Arr[13] = {0};
    char *pszAddr = NULL;
    uint8_t k1 = 0;
    uint8_t k2 = 0;
    uint8_t  i;

    skip_blanks(&p);

    printf("Input=%s\n", p);

    if(12 != check_length(p))
    {
        printf("\nInvalid Bd Address. Format[112233445566]\n");
        return FALSE;
    }
    memcpy(Arr, p, 12);

    for(i=0; i<12; i++)
    {
        Arr[i] = tolower(Arr[i]);
    }
    pszAddr = Arr;

    for(i=0; i<6; i++)
    {
        k1 = (uint8_t) ( (*pszAddr >= 'a') ?
            ( 10 + (uint8_t)( *pszAddr - 'a' )) : (*pszAddr - '0') );
        pszAddr++;
        k2 = (uint8_t) ( (*pszAddr >= 'a') ?
            ( 10 + (uint8_t)( *pszAddr - 'a' )) : (*pszAddr - '0') );
        pszAddr++;

        if ( (k1>15)||(k2>15) )
        {
            return FALSE;
        }
        pbd_addr->address[i] = (k1<<4 | k2);
    }
    return TRUE;
}
#endif //BAP_UNICAST_TEST_APP_INTERFACE
