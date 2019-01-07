static char const *USAGE = "Usage: <program>[-o file.tsv]\n"
     "\nThis program collects co2 readings from Zyaura sensors.\n"
     "Options:\n"
     "  -o file.tsv: write to a tab-separated-value file (otherwise to standard output)\n";

enum ProgramOption
{
     ProgramOption_OutputFile = 'o',
     NumProgramOptions,
};

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int zyaura_record_output_to_stream(FILE* stream);

int main(int argc, char **argv)
{
     char *output_filename = NULL;
     /* parse args */ {
          int argi = 1;
          char *error = NULL;
          while (argi < argc && !error) {
               char *arg = argv[argi];
               if (arg[0] == '-' && arg[1] == ProgramOption_OutputFile && !arg[2]) {
                    if (argi + 1 < argc) {
                         argi++;
                         output_filename = argv[argi++];
                    } else {
                         error = "Expected filename argument to -o";
                    }
               } else {
                    error = "Unknown argument";
               }
          }
          if (error) {
               int offset = 0;
               int error_first_offset = 0;
               int error_last_offset = 0;
               fprintf(stderr, "ERROR: ");
               for (int i = 0; i < argc; i++) {
                    int n_or_error = fprintf(stderr, "%s%s", i>0?" ":"", argv[i]);
                    if (n_or_error < 0) exit(-1);
                    if (i == argi) {
                         error_first_offset = offset + (i>0?1:0);
                    }
                    offset += n_or_error;
                    if (i == argi) {
                         error_last_offset = offset;
                    }
               }
               fprintf(stderr, "\nERROR: %*s", error_first_offset, " ");
               for (int i = error_first_offset; i < error_last_offset; i++) {
                    fprintf(stderr, "^");
               }
               fprintf(stderr, " %s\n\n%s\n", error, USAGE);
               return 1;
          }
     }
     FILE *output_stream = stdout;
     if (output_filename) {
          output_stream = fopen(output_filename, "wb");
	  if (!output_stream) {
              fprintf(stderr, "ERROR: could not open file %s for writing.\n", output_filename);
              return 1;
          }
	  // implicit fclose(output_stream), we let the OS do it for us
     }
     zyaura_record_output_to_stream(output_stream);
     return 0;
}

// References
//
// ZGm053U ZGm05 ZyAura

// @ur{https://habr.com/company/masterkit/blog/248403/}
// @url{https://hackaday.io/project/5301-reverse-engineering-a-low-cost-usb-co-monitor/log/17909-all-your-base-are-belong-to-us}
// @url{https://revspace.nl/CO2MeterHacking}
//
// ZyAura ZG-01 Module
// @url{http://www.zyaura.com/}
// @url{http://www.zyaura.com/support/manual/pdf/ZyAura_CO2_Monitor_ZG01%20Module%20English%20user%20manual_1205.pdf}
// @url{http://www.umarket.com.tw/ImguMarket/20080712085132.pdf}
// @url{http://www.zyaura.com/support/demo/ZG106_FW_001.ExtSpec.pdf}


#include "hidapi.h"

#define UU_HIDAPI_GUARD(x, msg) for (int err = x; err != 0; exit(1)) {	\
          fprintf(stderr, "unexpected hdiapi error: %d (%s)\n", -1, msg); \
     }

typedef struct UU_USB_Device
{
     hid_device *handle;
} UU_USB_Device;

typedef enum ZyAuraOpcode
{
     ZyAuraOpcode_RelativeHumidity = 'A', // 0x41,
     ZyAuraOpcode_Temperature = 'B', // 0x42,
     ZyAuraOpcode_Unknown_C = 'C', // 0x43,
     ZyAuraOpcode_Unknown_O = 'O', // 0x4f,
     ZyAuraOpcode_Relative_CO2_Concentration = 'P', // 0x50,
     ZyAuraOpcode_Unknown_R = 'R', // 0x52
     ZyAuraOpcode_Checksum_Error = 'S', // 0x53
     ZyAuraOpcode_Unknown_V = 'V', // 0x56
     ZyAuraOpcode_Unknown_W = 'W', // 0x57
     ZyAuraOpcode_Unknown_m = 'm', // 0x6d,
     ZyAuraOpcode_Unknown_n = 'n', // 0x6e,
     ZyAuraOpcode_Unknown_q = 'q', // 0x71,
} ZyAuraOpcode;

typedef struct ZyAuraReport
{
     ZyAuraOpcode opcode;
     uint16_t raw_value;
     union {
          int co2_in_ppm;
          float temperature_in_C;
          float relative_humidity;
     };
} ZyAuraReport;

UU_USB_Device uu_find_holtek_zytemp();
void uu_decrypt_holtek_zytemp_report(uint8_t const key[8], uint8_t data[8]);
ZyAuraReport unpack_holtek_zytemp_report(uint8_t decrypted_data[8]);

#if defined(WIN32)
struct tm* localtime_r(time_t *clock, struct tm *result)
{
    struct tm *p = localtime(clock);
    if (p) {
        *result = *p;
    }
    return p;
}
#endif

int zyaura_record_output_to_stream(FILE *out)
{
     assert(out);
     int rc = -1;
     UU_HIDAPI_GUARD(hid_init(), "hidapi: hid_init");
     UU_USB_Device device = uu_find_holtek_zytemp();
     if (!device.handle) {
          fprintf(stderr, "Could not find Holtek ZyTemp device\n");
          goto done;
     }

     // Send encoding key and start device
     unsigned char const key[] = {0xc4, 0xc6, 0xc0, 0x92, 0x40, 0x23, 0xdc, 0x96};
     {
        unsigned char msg[sizeof key + 1] = { 0x00, };
        // "The first byte of data[] must contain the Report-ID (note that hidapi
        // on the mac doesn't have this requirement, and silently drops the
        // initial zero)
        memcpy(&msg[1], &key[0], sizeof key);

        int num_bytes_or_error = hid_send_feature_report(device.handle, msg, sizeof msg);
        if (num_bytes_or_error != sizeof msg) {
            UU_HIDAPI_GUARD(num_bytes_or_error, "hidapi: device initialization (feature report)");
            exit(1);
        }
     }

     time_t prev_time_unix = time(NULL);
     fprintf(out, "Time\tReading\tValue\n");
     for (;;) {
          enum { INPUT_REPORT_SIZE = 8 };
          unsigned char msg[1 + INPUT_REPORT_SIZE] = {0, };
          // ^ "the first byte will contain the report number if the device
          // uses numbered reports"
          int num_bytes_or_error = hid_read(device.handle, msg, sizeof msg);
          if (num_bytes_or_error != sizeof msg &&
              num_bytes_or_error != INPUT_REPORT_SIZE) {
               UU_HIDAPI_GUARD(num_bytes_or_error, "hidapi: reading report");
               exit(1);
          }
          unsigned char data[INPUT_REPORT_SIZE];
          if (num_bytes_or_error == INPUT_REPORT_SIZE + 1) {
               // this happens on windows, the report is prefixed with
               // the report-id of zero:
               if (msg[0] != 0) {
                   fprintf(stderr, "ERROR: unexpected report from device (expected report-id 0)\n");
                  exit(1);
               }
               memcpy(&data[0], &msg[1], sizeof data);
          } else {
               memcpy(&data[0], &msg[0], sizeof data);
          }

          time_t now_unix = time(NULL);
          struct tm now_localtime;
          localtime_r(&now_unix, &now_localtime);

          uu_decrypt_holtek_zytemp_report(key, data);
          if (data[4] != 0x0d) {
               fprintf(stderr, "ERROR: missing terminator\n");
               exit(1);
          }
          if (data[3] != ((data[0] + data[1] + data[2]) & 0xff)) {
               fprintf(stderr, "ERROR: checksum\n");
               exit(1);
          }

          char time_string_buffer[4096];
          size_t time_string_len = strftime(&time_string_buffer[0], sizeof time_string_buffer, "%Y-%m-%dT%H:%M:%S", &now_localtime);
          assert(time_string_len);

          struct ZyAuraReport report = unpack_holtek_zytemp_report(data);
          switch (report.opcode) {
          case ZyAuraOpcode_Relative_CO2_Concentration: {
               fprintf(out, "%*s\tCO2\t%d\n", (int)time_string_len, time_string_buffer, report.co2_in_ppm);
               break;
          }

          case ZyAuraOpcode_Temperature: {
               fprintf(out, "%*s\tTemperature\t%f\n", (int)time_string_len, time_string_buffer, report.temperature_in_C);
               break;
          }

          case ZyAuraOpcode_RelativeHumidity: {
               // Our ZG01CV does not support relative humidity. The opcode is
               // being received but reads always as zero. So we disable it.
               //
               // fprintf(out, "Relative Humidity: %f %%\n", report.relative_humidity);
               break;
          }

          case ZyAuraOpcode_Checksum_Error: {
               fprintf(out, "%*s\t<Module returned checksum error>\n", (int)time_string_len, time_string_buffer); // this should happen on write.
          }

          case ZyAuraOpcode_Unknown_C:
          case ZyAuraOpcode_Unknown_O:
          case ZyAuraOpcode_Unknown_R:
          case ZyAuraOpcode_Unknown_W:
          case ZyAuraOpcode_Unknown_V:
          case ZyAuraOpcode_Unknown_m:
          case ZyAuraOpcode_Unknown_n:
          case ZyAuraOpcode_Unknown_q: {
#if 0
               // These report numbers are received regularly, but we don't know
               // what they mean, and what info they're carrying.
               fprintf(out, "<Unknown Opcode: 0x%x '%c'>\t%d\n", report.opcode, (char) report.opcode, report.raw_value);
#endif
               break;
          }

          default: {
               fprintf(out, "%*s\t<Unexpected Opcode: 0x%x '%c'\t%d\n", (int)time_string_len, time_string_buffer, report.opcode, (char) report.opcode, report.raw_value);
               break;
          }
          }

          if (now_unix - prev_time_unix > 0)  fflush(out);
          prev_time_unix = now_unix;
     }

     rc = 0;
done:
     hid_exit();
     return rc;
}

UU_USB_Device uu_find_holtek_zytemp()
{
     return (struct UU_USB_Device){ .handle = hid_open(0x04d9, 0xa052, NULL) };
}


void uu_decrypt_holtek_zytemp_report(uint8_t const key[8], uint8_t data[8])
{
     int shuffle[8] = { 2, 4, 0, 7, 1, 6, 5, 3 };

     uint8_t temp[8] = { 0, };
     for (int i = 0; i < 8; i++) {
          int di = shuffle[i];
          temp[di] = data[i];
          temp[di] ^= key[di];
     }

     uint8_t temp1[8] = {0,};
     for (int i = 0; i < 8; i++) {
          int oi = (i - 1 + 8) & 7;
          temp1[i] = (((temp[i]>>3) & 31) | (temp[oi]<<5)) & 0xff;
     }

     uint8_t cstate[8] = {'H', 't', 'e', 'm', 'p', '9', '9', 'e'}; // salt
     uint8_t ctemp[8] = { 0, };
     for (int i = 0; i < 8; i++) {
          ctemp[i] = ((cstate[i] >> 4) & 15) | (cstate[i]<<4);
     }

     for (int i = 0; i < 8; i++) {
          data[i] = 0x100 + temp1[i] - ctemp[i];
     }
}

ZyAuraReport unpack_holtek_zytemp_report(uint8_t decrypted_data[8])
{
     ZyAuraReport Result;
     Result.opcode = decrypted_data[0];
     Result.raw_value = (decrypted_data[1]<<8) | decrypted_data[2];

     switch (Result.opcode) {
     case ZyAuraOpcode_Relative_CO2_Concentration:
          Result.co2_in_ppm = Result.raw_value;
          break;
     case ZyAuraOpcode_Temperature:
          Result.temperature_in_C = Result.raw_value/16.0 - 273.15;
          break;
     case ZyAuraOpcode_RelativeHumidity:
          Result.relative_humidity = Result.raw_value/100.0;
          break;
     default:
          break;
     }

     return Result;
}

// Spec
//
// Modes: ComMasterMode, EndUserMaster, SlaveMode
// - ComMasterMode: CO2/Temp Data can be read, Calibration can be done, Reset
// - EndUserMaster: CO2/Temp Data can be read, Calibration cannot be done, Reset no
// - Slave: for multisensor applications
//
// Under master modes, sensor data is being sent continuously.
// Under slave mode, response to commands:
// - 0x23 0x31 0x30 0x0d -> will produce CO2 reading
// - 0x23 0x31 0x31 0x0d -> will produce temperature reading
// - 0x23 0x31 0x32 0x0d -> will produce relative humidity reading
//

// For writing the format is the same as for reading:
//
// ItemCode:u8, HighByte:u8, LowByte:u8, Checksum(ItemCode+HighByte+LowByte), 0xd
//
// | Item Code | Desc                         | Mode          |
// +-----------+------------------------------+---------------+
// | 0x4d      | Altitude/Emissivity          |               |
// | 0x5d ']'  | Setting or writing parameter | ComMasterMode |
// | 0x65 'e'  | Gain parameter               | ComMasterMode |
//
// 0x5d, msb: uint16, lsb: uint16, checksum: uint16, 0xd
// When pumping the reference gas at 100ppm, write FF9C (-100 decimal) into the 0x5d parameter
//
// Switching modes:
//
// EndUserMaster > ComMaster = 0x02 0x51 0x30 0x32 0x30 0x31 0x35 0x34 0x0d
// ComMaster > Slave = 0x23 0x31 0x35 0x0d
// Slave > ComMaster = 0x23 0x31 0x35 0x0d
// ComMaster > EndUserMaster = 0x02 0x51 0x30 0x32 0x34 0x31 0x39 0x34 0x0D
