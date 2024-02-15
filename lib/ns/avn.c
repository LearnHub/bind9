#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>

#include <isc/aes.h>
#include <isc/atomic.h>
#include <isc/formatcheck.h>
#include <isc/fuzz.h>
#include <isc/hmac.h>
#include <isc/log.h>
#include <isc/mutex.h>
#include <isc/nonce.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/random.h>
#include <isc/safe.h>
#include <isc/serial.h>
#include <isc/siphash.h>
#include <isc/stats.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/adb.h>
#include <dns/badcache.h>
#include <dns/cache.h>
#include <dns/db.h>
#include <dns/dispatch.h>
#include <dns/dnstap.h>
#include <dns/edns.h>
#include <dns/events.h>
#include <dns/message.h>
#include <dns/peer.h>
#include <dns/rcode.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/resolver.h>
#include <dns/result.h>
#include <dns/stats.h>
#include <dns/tsig.h>
#include <dns/view.h>
#include <dns/zone.h>

#include <ns/client.h>
#include <ns/interfacemgr.h>
#include <ns/log.h>
#include <ns/notify.h>
#include <ns/server.h>
#include <ns/stats.h>
#include <ns/avn.h>

static bool avn_validate_number(char* str) {
  while (*str) {
    if (!isdigit(*str)) {
      return false;
    }
    str++;
  }
  return true;
}

isc_result_t
avn_verify_response(ns_client_t *client, isc_region_t *region) {
	ns_client_log(client, DNS_LOGCATEGORY_SECURITY,
				      NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				      "avn_verify_response: Region.base=%p, Region.len=%d",
				      region->base, region->length);
	
	uint16_t transactionId = region->base[1] + (region->base[0] << 8);
	uint16_t flags = region->base[3] + (region->base[2] << 8);
	uint16_t Qs = region->base[5] + (region->base[4] << 8);
	uint16_t As = region->base[7] + (region->base[6] << 8);
	uint16_t Auths = region->base[9] + (region->base[8] << 8);
	uint16_t Adds = region->base[11] + (region->base[10] << 8);
	
	ns_client_log(client, DNS_LOGCATEGORY_SECURITY,
				      NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				      "avn_verify_response: transactionId=0x%x, flags=0x%x",
				      transactionId, flags);

	ns_client_log(client, DNS_LOGCATEGORY_SECURITY,
				      NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				      "avn_verify_response: Questions:%d, Answers:%d, AuthRRs:%d, AdditionalRRs:%d",
				      Qs, As, Auths, Adds);

	unsigned char host[DNS_NAME_FORMATSIZE];

	unsigned char *p = region->base + 12;
	// We expect the host to be of the form "aaa-bbb-ccc-ddd.avnlan.link"
	uint8_t len = *p;
	// Min length = 7 (a-b-c-d), Max length 15 (aaa-bbb-ccc-ddd)
	if (len > 6 && len < 16) {
		uint8_t* d = p + len + 1;
		if (d[0] == 6 && d[1] == 'a' && d[2] == 'v' && d[3] == 'n' && d[4] == 'l'
				&& d[5] == 'a' && d[6] == 'n' && d[7] == 4 && d[8] == 'l'
				&& d[9] == 'i' && d[10] == 'n' && d[11] == 'k' && d[12] == 0) {
			strncpy(host, p + 1, len);
			host[len] = 0;
			ns_client_log(client, DNS_LOGCATEGORY_SECURITY, NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
					  "avn_verify_response: attempting to decode host '%s'", host);

			int dashes = 0;
			unsigned char ipAddr[4];

			char* ptr = strtok(host, "-");
			while (ptr) {
				if (avn_validate_number(ptr)) {
					int num = atoi(ptr);
					if (num >= 0 && num <= 255) {
						ipAddr[dashes] = num;
						ptr = strtok(NULL, "-");
						if (NULL != ptr) {
							dashes++;
						} else {
							break;
						}
					} else {
						break;
					}
				} else {
					break;
				}
			}

			if (dashes == 3) {
				ns_client_log(client, DNS_LOGCATEGORY_SECURITY, NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
					  "avn_verify_response: decoded IP -> %d.%d.%d.%d", ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);

				uint8_t* pResolvedIP = p + len + 1 + 13 + 4 + 12;

				ns_client_log(client, DNS_LOGCATEGORY_SECURITY, NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
					  "avn_verify_response: Current buffer content -> %d.%d.%d.%d", 
					  pResolvedIP[0], pResolvedIP[1], pResolvedIP[2], pResolvedIP[3]);

				if ( (pResolvedIP[0] != ipAddr[0]) || (pResolvedIP[1] != ipAddr[1]) ||
					 (pResolvedIP[2] != ipAddr[2]) || (pResolvedIP[3] != ipAddr[3]) ) {

					ns_client_log(client, DNS_LOGCATEGORY_SECURITY, NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
					  "avn_verify_response: %d.%d.%d.%d != %d.%d.%d.%d - overwriting...", 
					  pResolvedIP[0], pResolvedIP[1], pResolvedIP[2], pResolvedIP[3],
					  ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);

					pResolvedIP[0] = ipAddr[0];
					pResolvedIP[1] = ipAddr[1];
					pResolvedIP[2] = ipAddr[2];
					pResolvedIP[3] = ipAddr[3];
				}

			}
		}
	}

	return ISC_R_SUCCESS;
}
