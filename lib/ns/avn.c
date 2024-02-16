#include <ctype.h>
#include <math.h>

#include <ns/client.h>
#include <ns/log.h>
#include <ns/avn.h>

static isc_mutex_t _strtok_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct avn_dns_response_top {
    uint16_t _transaction_id;
    uint16_t _flags;
    uint16_t _questions;
    uint16_t _answers;
    uint16_t _authority_RRs;
    uint16_t _additional_RRs;
} avn_dns_response_top_t ;

#pragma pack(push, 1)
typedef struct avn_dns_response_tail {
    uint16_t _req_type;
    uint16_t _req_class;
    uint16_t _host_ref;
    uint16_t _resp_type;
	uint16_t _resp_class;
    uint32_t _ttl;
	uint16_t _data_len;
    char _ip[4];
} avn_dns_response_tail_t ;
#pragma pack(pop)

static uint16_t getLE16Val(uint16_t in) {
    return (in >> 8) | (in << 8) ;
}

static void avn_dump_memory(ns_client_t *client, uint8_t *buf, uint32_t len) {
	ns_client_log(client, DNS_LOGCATEGORY_SECURITY, NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				"avn_hex_dump: buf %p, length = %d", buf, len);

	uint32_t bytes_left = len;
	uint8_t* iterP = buf;
	char hex[DNS_NAME_FORMATSIZE];
	char print[DNS_NAME_FORMATSIZE];
	while (0 < bytes_left) {
		memset(hex, 0, DNS_NAME_FORMATSIZE);
		memset(print, 0, DNS_NAME_FORMATSIZE);
		uint32_t line_len = (bytes_left > 16) ? 16 : bytes_left;
		
		char* px = hex;
		char* pp = print;
		for (uint32_t i = 0 ; i < line_len ; i++) {
			snprintf(px, 4, "%02x ", iterP[i]);
			px += 3;
			snprintf(pp, 2, "%c", (isprint(iterP[i]) ? iterP[i] : '.'));
			pp += 1;
		}

		ns_client_log(client, DNS_LOGCATEGORY_SECURITY, NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				"avn_hex_dump: %-48s--- %s", hex, print);

		bytes_left -= line_len;
		iterP += line_len;
	}
}

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
	/*ns_client_log(client, DNS_LOGCATEGORY_SECURITY,
				      NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				      "avn_verify_response: Region.base=%p, Region.len=%d",
				      region->base, region->length);*/
	
    avn_dns_response_top_t *pRespTop = (avn_dns_response_top_t *) region->base;
	
	/*uint16_t dnsFlags = getLE16Val(pRespTop->_flags);

    ns_client_log(client, DNS_LOGCATEGORY_SECURITY,
				      NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				      "avn_verify_response: transactionId=0x%x, flags=0x%x",
				      getLE16Val(pRespTop->_transaction_id), dnsFlags);

    if (0x8400 != dnsFlags && 0x8580 != dnsFlags) {
	    ns_client_log(client, DNS_LOGCATEGORY_SECURITY,
				      NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				      "avn_verify_response: bypassing response - UNEXPECTED DNS flags=0x%x", dnsFlags);
		return ISC_R_UNEXPECTED;	
	}*/

	uint16_t Qs = getLE16Val(pRespTop->_questions);
	uint16_t As = getLE16Val(pRespTop->_answers);
	uint16_t Auths = getLE16Val(pRespTop->_authority_RRs);
	uint16_t Adds = getLE16Val(pRespTop->_additional_RRs);

	if (0 == As) {
		// No answer in this response, so we don't need to touch it.
		return ISC_R_UNEXPECTED;
	} else {
		if ( (1 != Qs) || (1 != As) /*|| (0 != Auths) || (0 != Adds)*/ ) {
			ns_client_log(client, DNS_LOGCATEGORY_SECURITY,
						NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
						"avn_verify_response: Questions:%d, Answers:%d, AuthRRs:%d, AdditionalRRs:%d",
						Qs, As, Auths, Adds);

			ns_client_log(client, DNS_LOGCATEGORY_SECURITY,
						NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
						"avn_verify_response: bypassing response - UNEXPECTED RRs (should be Q's:1, A's:1)");
			return ISC_R_UNEXPECTED;	
		}
	}

	char *p = (char*) (region->base + 12);
	uint8_t len = *p;
	// Min length = 7 (a-b-c-d), Max length 15 (aaa-bbb-ccc-ddd)
	if (len > 6 && len < 16) {
		char* d = p + len + 1;
		if ( (d[0] == 6) && 
				( d[1] == 'a' || d[1] == 'A' ) && 
				( d[2] == 'v' || d[2] == 'V' ) && 
				( d[3] == 'n' || d[3] == 'N' ) && 
				( d[4] == 'l' || d[4] == 'L' ) && 
				( d[5] == 'a' || d[5] == 'A' ) && 
				( d[6] == 'n' || d[6] == 'N' ) && 
			  (d[7] == 4) && 
			  	( d[8] == 'l' || d[8] == 'L') &&
				( d[9] == 'i' || d[9] == 'I') &&
				( d[10] == 'n' || d[10] == 'N') &&
				( d[11] == 'k' || d[11] == 'K') &&
			  (d[12] == 0) ) {
			char host[DNS_NAME_FORMATSIZE];
			strncpy(host, p + 1, len);
			host[len] = 0;
			int dashes = 0;
			unsigned char ipAddr[4];

			char tokenHost[DNS_NAME_FORMATSIZE];
			strncpy(tokenHost, host, len);
			tokenHost[len] = 0;
			
			// strtok is NOT thread-safe so we need to protect dashed-IP parsing.
			LOCK(&_strtok_lock);
			
			char* ptr = strtok(tokenHost, "-");
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

			UNLOCK(&_strtok_lock);

			if (dashes == 3) {
				ns_client_log(client, DNS_LOGCATEGORY_SECURITY, NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
					  "avn_verify_response: decoded '%s' -> IP %d.%d.%d.%d", host, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);

				avn_dns_response_tail_t* pRespTail = (avn_dns_response_tail_t*)(p + len + 1 + 13);

				//char* pResolvedIP = p + len + 1 + 13 + 4 + 12;

				if ( (0x0100 == pRespTail->_req_type) && (0x0100 == pRespTail->_req_class) ) {
					char* pIPData = NULL;

					if (0x0cc0 == pRespTail->_host_ref) {
						pIPData = (char*)(p + len + 1 + 13 + 4 + 12);
					} else {
						// Looks like the fqdn has been duplicated in the answer.
						// We need to jump passed it to find the IP data bytes.

						char* start = (char*) &(pRespTail->_host_ref);
						//avn_dump_memory(client, region->base, region->length);

						char* iterP = start;
						uint16_t host_len = 0;
						while (0 != *iterP) {
							int8_t rlen = *iterP;
							host_len += rlen + 1;
							iterP = start + host_len;
						}
						pIPData = ((char*) &(pRespTail->_host_ref)) + host_len + 1 + 10;
					}
					
					if ( (NULL != pIPData) && (pIPData[0] == 9) && (pIPData[1] == 8) && (pIPData[2] == 7) && (pIPData[3] == 6) ) {
						pIPData[0] = ipAddr[0];
						pIPData[1] = ipAddr[1];
						pIPData[2] = ipAddr[2];
						pIPData[3] = ipAddr[3];
					} else {
						ns_client_log(client, DNS_LOGCATEGORY_SECURITY, NS_LOGMODULE_CLIENT, ISC_LOG_ERROR,
						"avn_verify_response: Unexpected content in buffer -> %d.%d.%d.%d", 
						pIPData[0], pIPData[1], pIPData[2], pIPData[3]);

						return ISC_R_UNEXPECTED;
					}
				} else {
					// Either the request is not an A-type record or it's not IN class, so disregard it.
					return ISC_R_UNEXPECTED;
				}	
			} else {
				ns_client_log(client, DNS_LOGCATEGORY_SECURITY, NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				      "avn_verify_response: bypassing response - failed to parse '%s' - found %d dashes", host, dashes);
				avn_dump_memory(client, (unsigned char*) tokenHost, 16);
				return ISC_R_UNEXPECTED;
			}
		} else {
			ns_client_log(client, DNS_LOGCATEGORY_SECURITY, NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				      "avn_verify_response: bypassing response - domain is not 'avnlan.link'");
			return ISC_R_UNEXPECTED;
		}
	} else {
	    ns_client_log(client, DNS_LOGCATEGORY_SECURITY,
				      NS_LOGMODULE_CLIENT, ISC_LOG_INFO,
				      "avn_verify_response: bypassing response - hostname len is %d"
					  " - so it cannot be a valid dashed-IP format", len);
		return ISC_R_UNEXPECTED;	
	}

	return ISC_R_SUCCESS;
}

