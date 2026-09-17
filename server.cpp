
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <string>
#include <vector>
#include <istream>
#include <sstream>
#include <thread>

#ifdef _WIN32
/* ================= Windows 平台 ================= */
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include "hook.h"

#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "Crypt32.lib")
#  pragma comment(lib, "libssl_static.lib")
#  pragma comment(lib, "libcrypto_static.lib")

/* 静态 OpenSSL 链接所需的 MSVC 辅助符号 */
extern "C" unsigned __int64 _dtoul3_legacy(double v) { return (unsigned __int64)llround(v); }

#else
/* ================= Linux/POSIX 平台 ================= */
#  include <unistd.h>
#  include <fcntl.h>
#  include <signal.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>

typedef int SOCKET;
#  define INVALID_SOCKET (-1)
#  define closesocket(s) ::close(s)

/* MSVC secure CRT 兼容层 */
static inline int sprintf_s(char* s, size_t n, const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int r = vsnprintf(s, n, fmt, ap);
	va_end(ap);
	return r;
}
static inline int memcpy_s(void* dst, size_t dstsz, const void* src, size_t n)
{
	if (n > dstsz) return -1;
	memcpy(dst, src, n);
	return 0;
}
static inline int strcat_s(char* dst, size_t sz, const char* src)
{
	size_t l = strlen(dst);
	size_t m = strlen(src);
	if (l + m + 1 > sz) return -1;
	memcpy(dst + l, src, m + 1);
	return 0;
}
#endif

#include <openssl/ts.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/asn1.h>

#define LISTEN_PORT 8080
#define BUF_SIZE 4096


EVP_PKEY* g_tsa_pkey = NULL;
X509* g_tsa_cert = NULL;
X509* g_tsa_ca = NULL;
ASN1_OBJECT* g_ts_policy = NULL;

/* legacy Authenticode countersignature protocol assets */
X509* g_legacy_cert = NULL;
EVP_PKEY* g_legacy_pkey = NULL;
#define SPC_TIMESTAMP_REQUEST_OID "1.3.6.1.4.1.311.3.2.1"

/* 时间 API 内联 hook 仅 Windows 使用；
 * Linux 下伪造时间由 RFC3161 回调 / fake_utctime_now() 直接从 ini 生成 */
#ifdef _WIN32
hook g_GetSystemTimeAsFileTime;
hook g_GetSystemTimePreciseAsFileTime;
hook g_ZwQuerySystemTime;
#endif

std::vector<std::string> SplitString(const std::string& str, char delimiter)
{
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(str);
	while (std::getline(tokenStream, token, delimiter)) {
		for (size_t i = 0; i < token.length(); i++)
		{
			if (token[i] == '\r')
			{
				token[i] = 0;   /* 去掉 Windows 行尾的 \r，后续按 C 字符串截断 */
			}
		}
		std::string str = token.c_str();

		tokens.push_back(str);
	}
	return tokens;
}

/* 获取可执行文件所在目录（带结尾分隔符）；失败返回空串 */
static std::string get_exe_dir()
{
#ifdef _WIN32
	char path[MAX_PATH] = { 0 };
	DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
	if (n == 0 || n >= MAX_PATH) return std::string();
	char* slash = strrchr(path, '\\');
	if (slash) slash[1] = 0; else path[0] = 0;
	return std::string(path);
#else
	char path[4096] = { 0 };
	ssize_t n = ::readlink("/proc/self/exe", path, sizeof(path) - 1);
	if (n <= 0) return std::string();
	path[n] = 0;
	char* slash = strrchr(path, '/');
	if (slash) slash[1] = 0; else path[0] = 0;
	return std::string(path);
#endif
}

/* 拼接可执行文件同目录下的资源文件（如 HookSigntool.ini） */
static std::string exe_dir_file(const char* name)
{
	return get_exe_dir() + name;
}

long IsFileExist(const std::string& file)
{
#ifdef _WIN32
	struct _stat64 st;
	if (_stat64(file.c_str(), &st) != 0) return 0;
	return (st.st_mode & _S_IFREG) ? 1 : 0;
#else
	struct stat st;
	if (stat(file.c_str(), &st) != 0) return 0;
	return S_ISREG(st.st_mode) ? 1 : 0;
#endif
}

std::string MyReadFile(const std::string& file)
{
	std::string content;
	FILE* fp = fopen(file.c_str(), "rb");
	if (!fp) {
		return content;
	}

	if (fseek(fp, 0, SEEK_END) == 0)
	{
		long fsize = ftell(fp);
		if (fsize > 0)
		{
			rewind(fp);
			content.resize((size_t)fsize);
			size_t rd = fread(&content[0], 1, content.size(), fp);
			if (rd != content.size()) {
				content.clear();
			}
		}
	}

	fclose(fp);
	return content;
}

long MyWriteFile(const std::string& file, const std::string& content)
{
	/* 与旧逻辑一致：不存在则创建，存在则追加到文件尾 */
	FILE* fp = fopen(file.c_str(), "ab");
	if (!fp) {
		return 0;
	}

	size_t wr = fwrite(content.data(), 1, content.size(), fp);
	fclose(fp);

	return wr == content.size() ? 1 : 0;
}

/* ========================================================================
 * 伪造时间统一入口
 *
 * HookSigntool.ini 存的是本地挂钟时间（北京时间），字段顺序：
 *   year / weekday / month / day / hour / minute / second / millisecond
 * ini 位于可执行文件同目录；缺失或格式错误时写入默认值 2018-10-06 20:05:50.350。
 * 解析结果在进程内缓存（与旧逻辑一致）。
 * ======================================================================== */
struct FakeFields
{
	int year;
	int weekday;
	int month;
	int day;
	int hour;
	int minute;
	int second;
	int millisecond;
};

static void fake_read_fields(FakeFields* f)
{
	static FakeFields cache = { 0 };
	static bool loaded = false;
	if (loaded) { *f = cache; return; }

	static const char* default_ini =
		"2018\n"
		"6\n"
		"10\n"
		"6\n"
		"20\n"
		"5\n"
		"50\n"
		"350";

	bool ok = false;
	std::string ini = exe_dir_file("HookSigntool.ini");
	if (IsFileExist(ini))
	{
		std::string str = MyReadFile(ini);
		if (!str.empty())
		{
			std::vector<std::string> v = SplitString(str, '\n');
			if (v.size() == 8)
			{
				cache.year        = atoi(v[0].c_str());
				cache.weekday     = atoi(v[1].c_str());
				cache.month       = atoi(v[2].c_str());
				cache.day         = atoi(v[3].c_str());
				cache.hour        = atoi(v[4].c_str());
				cache.minute      = atoi(v[5].c_str());
				cache.second      = atoi(v[6].c_str());
				cache.millisecond = atoi(v[7].c_str());
				ok = true;
			}
		}
	}

	if (!ok)
	{
		remove(ini.c_str());
		MyWriteFile(ini, default_ini);
		cache.year        = 2018;
		cache.weekday     = 6;
		cache.month       = 10;
		cache.day         = 6;
		cache.hour        = 20;
		cache.minute      = 5;
		cache.second      = 50;
		cache.millisecond = 350;
	}

	loaded = true;
	*f = cache;
}

/* 伪造时间换算后的 UTC 结果（供两种时间戳协议共用） */
struct FakeUtc
{
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
	int millisecond;
	long epoch_sec;   /* 自 1970-01-01 00:00:00 UTC 起的秒数 */
};

#ifdef _WIN32
/* -------- Windows：保留原有 SYSTEMTIME -> FILETIME + 时区偏移算法 -------- */

static BOOL IsLeapYear(WORD year)
{
	return ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
}

static BOOL MySystemTimeToFileTime(const SYSTEMTIME* st, LPFILETIME ft)
{
	static const WORD days_in_month[12] = { 31,28,31,30,31,30,31,31,30,31,30,31 };
	ULARGE_INTEGER ul = { 0 };
	WORD y = st->wYear;
	WORD m = st->wMonth;
	WORD d = st->wDay;

	if (y < 1601 || m < 1 || m >12 || d < 1 || d>31)
		return FALSE;


	for (WORD yy = 1601; yy < y; yy++)
	{
		ul.QuadPart += IsLeapYear(yy) ? 366ULL : 365ULL;
	}

	for (WORD mm = 1; mm < m; mm++)
	{
		ul.QuadPart += days_in_month[mm - 1];
		if (mm == 2 && IsLeapYear(y))
			ul.QuadPart += 1;
	}
	ul.QuadPart += (d - 1);


	ul.QuadPart = ul.QuadPart * 864000000000ULL;
	ul.QuadPart += (ULONGLONG)st->wHour * 36000000000ULL;
	ul.QuadPart += (ULONGLONG)st->wMinute * 600000000ULL;
	ul.QuadPart += (ULONGLONG)st->wSecond * 10000000ULL;
	ul.QuadPart += (ULONGLONG)st->wMilliseconds * 10000ULL;

	ft->dwLowDateTime = ul.LowPart;
	ft->dwHighDateTime = ul.HighPart;
	return TRUE;
}

static void fake_local_systemtime(LPSYSTEMTIME lpSystemTime)
{
	FakeFields f = { 0 };
	fake_read_fields(&f);
	memset(lpSystemTime, 0, sizeof(SYSTEMTIME));
	lpSystemTime->wYear = (WORD)f.year;
	lpSystemTime->wMonth = (WORD)f.month;
	lpSystemTime->wDayOfWeek = (WORD)f.weekday;
	lpSystemTime->wDay = (WORD)f.day;
	lpSystemTime->wHour = (WORD)f.hour;
	lpSystemTime->wMinute = (WORD)f.minute;
	lpSystemTime->wSecond = (WORD)f.second;
	lpSystemTime->wMilliseconds = (WORD)f.millisecond;
}

/* ini 本地时间 -> UTC FILETIME，hook 回调与时间戳生成共用 */
static void fake_local_to_utc_filetime(LPFILETIME lpSystemTimeAsFileTime)
{
	SYSTEMTIME SystemTime = { 0 };
	fake_local_systemtime(&SystemTime);
	MySystemTimeToFileTime(&SystemTime, lpSystemTimeAsFileTime);

	// The fake SYSTEMTIME is the user's LOCAL wall-clock time (Beijing),
	// while FILETIME is UTC. UTC = local + Bias; Beijing Bias is -480 min,
	// so this subtracts 8 hours (e.g. 20:05:50 local -> 12:05:50 UTC).
	TIME_ZONE_INFORMATION tzi;
	DWORD tz = GetTimeZoneInformation(&tzi);
	LONG bias = tzi.Bias;
	if (tz == TIME_ZONE_ID_DAYLIGHT)
		bias += tzi.DaylightBias;
	ULARGE_INTEGER ul;
	ul.LowPart = lpSystemTimeAsFileTime->dwLowDateTime;
	ul.HighPart = lpSystemTimeAsFileTime->dwHighDateTime;
	ul.QuadPart += (LONGLONG)bias * 600000000LL;
	lpSystemTimeAsFileTime->dwLowDateTime = ul.LowPart;
	lpSystemTimeAsFileTime->dwHighDateTime = ul.HighPart;
}

VOID WINAPI MyGetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
	if (lpSystemTimeAsFileTime == NULL)
		return;
	fake_local_to_utc_filetime(lpSystemTimeAsFileTime);
}

NTSTATUS MyZwQuerySystemTime(PLARGE_INTEGER SystemTime)
{
	fake_local_to_utc_filetime((LPFILETIME)SystemTime);
	return S_OK;
}

static void fake_get_utc(FakeUtc* out)
{
	FILETIME ft;
	fake_local_to_utc_filetime(&ft);

	SYSTEMTIME st = { 0 };
	FileTimeToSystemTime(&ft, &st);
	ULARGE_INTEGER ul;
	ul.LowPart = ft.dwLowDateTime;
	ul.HighPart = ft.dwHighDateTime;

	out->year        = st.wYear;
	out->month       = st.wMonth;
	out->day         = st.wDay;
	out->hour        = st.wHour;
	out->minute      = st.wMinute;
	out->second      = st.wSecond;
	out->millisecond = st.wMilliseconds;
	out->epoch_sec   = (long)((ul.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

#else
/* -------- Linux：ini 本地时间经 mktime 按系统时区换算为 UTC -------- */

static void fake_get_utc(FakeUtc* out)
{
	FakeFields f = { 0 };
	fake_read_fields(&f);

	struct tm local = { 0 };
	local.tm_year  = f.year - 1900;
	local.tm_mon   = f.month - 1;
	local.tm_mday  = f.day;
	local.tm_hour  = f.hour;
	local.tm_min   = f.minute;
	local.tm_sec   = f.second;
	local.tm_isdst = -1;                 /* 由系统判断是否夏令时 */
	time_t t = mktime(&local);           /* 按系统时区把本地时间转成 UTC epoch */

	struct tm utc = { 0 };
	gmtime_r(&t, &utc);

	out->year        = utc.tm_year + 1900;
	out->month       = utc.tm_mon + 1;
	out->day         = utc.tm_mday;
	out->hour        = utc.tm_hour;
	out->minute      = utc.tm_min;
	out->second      = utc.tm_sec;
	out->millisecond = f.millisecond;
	out->epoch_sec   = (long)t;
}

#endif


static void tsa_log(const char* tag, const char* detail);
static ASN1_UTCTIME* fake_utctime_now(void)
{
	FakeUtc u = { 0 };
	fake_get_utc(&u);

	ASN1_UTCTIME* ut = ASN1_UTCTIME_new();
	if (!ut)
		return NULL;
	char buf[32];
	sprintf_s(buf, sizeof(buf), "%02d%02d%02d%02d%02d%02dZ",
		u.year % 100, u.month, u.day,
		u.hour, u.minute, u.second);
	if (!ASN1_UTCTIME_set_string(ut, buf))
	{
		ASN1_UTCTIME_free(ut);
		return NULL;
	}
	{
		char lb[80];
		sprintf_s(lb, sizeof(lb), "signingTime=%s", buf);
		tsa_log("legacy OK", lb);
	}
	return ut;
}

/* 审计日志：打印真实系统时间（不是伪造时间），便于核对请求时刻 */
static void tsa_log(const char* tag, const char* detail)
{
	int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;

#ifdef _WIN32
	SYSTEMTIME st = { 0 };
	HMODULE nt = GetModuleHandleA("ntdll.dll");
	typedef LONG (WINAPI* PFN_NtQuerySystemTime)(PLONGLONG);
	PFN_NtQuerySystemTime pNt = nt ? (PFN_NtQuerySystemTime)GetProcAddress(nt, "NtQuerySystemTime") : NULL;
	if (pNt)
	{
		LONGLONG q = 0;
		if (pNt(&q) == 0)
		{
			FILETIME ft;
			ft.dwLowDateTime = (DWORD)q;
			ft.dwHighDateTime = (DWORD)(q >> 32);
			SYSTEMTIME utc;
			if (FileTimeToSystemTime(&ft, &utc))
			{
				TIME_ZONE_INFORMATION tz;
				DWORD r = GetTimeZoneInformation(&tz);
				if (r != TIME_ZONE_ID_INVALID)
					(void)SystemTimeToTzSpecificLocalTime(&tz, &utc, &st);
				else
					st = utc;
			}
		}
	}
	year = st.wYear; month = st.wMonth; day = st.wDay;
	hour = st.wHour; minute = st.wMinute; second = st.wSecond;
#else
	time_t now = time(NULL);
	struct tm st;
	localtime_r(&now, &st);
	year = st.tm_year + 1900;
	month = st.tm_mon + 1;
	day = st.tm_mday;
	hour = st.tm_hour;
	minute = st.tm_min;
	second = st.tm_sec;
#endif

	printf("%04d-%02d-%02d %02d:%02d:%02d  %-12s  %s\n",
		year, month, day, hour, minute, second,
		tag ? tag : "", detail ? detail : "");
}


static int load_tsa_cert_key(const char* cert_path, const char* key_path, const char* ca_path)
{
	

	BIO* bio = BIO_new_file(cert_path, "r");
	if (!bio)
	{
		fprintf(stderr, "无法打开证书文件: %s\n", cert_path);
		return 0;
	}
	g_tsa_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!g_tsa_cert)
	{
		ERR_print_errors_fp(stderr);
		return 0;
	}

	bio = BIO_new_file(key_path, "r");
	if (!bio)
	{
		fprintf(stderr, "无法打开私钥文件: %s\n", key_path);
		return 0;
	}
	g_tsa_pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!g_tsa_pkey)
	{
		ERR_print_errors_fp(stderr);
		return 0;
	}

// policy OID
	g_ts_policy = OBJ_txt2obj("1.2.3.4.5.6.7.8", 1);
	if (!g_ts_policy)
	{
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (ca_path)
	{
		bio = BIO_new_file(ca_path, "r");
		if (bio)
		{
			g_tsa_ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);
			BIO_free(bio);
		}
	}
	return 1;
}



static int load_legacy_assets(const char* cert_path, const char* key_path)
{
	BIO* bio = BIO_new_file(cert_path, "r");
	if (!bio) { 
		fprintf(stderr, "无法打开旧版证书: %s\n", cert_path);
		return 0; 
	}
	g_legacy_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!g_legacy_cert) { ERR_print_errors_fp(stderr); return 0; }

	bio = BIO_new_file(key_path, "r");
	if (!bio) { 
		fprintf(stderr, "无法打开旧版私钥: %s\n", key_path);
		return 0; }
	g_legacy_pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!g_legacy_pkey) { ERR_print_errors_fp(stderr); return 0; }
	return 1;
}


static int b64_strip_decode(const unsigned char* in, int in_len,
	unsigned char** out, int* out_len)
{
	char* clean = (char*)malloc(in_len + 4);
	if (!clean) return -1;
	int j = 0;
	for (int i = 0; i < in_len; ++i)
	{
		unsigned char c = in[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
			clean[j++] = (char)c;
	}
	while (j % 4) clean[j++] = '=';
	clean[j] = 0;

	int pads = 0;
	if (j >= 1 && clean[j - 1] == '=') pads++;
	if (j >= 2 && clean[j - 2] == '=') pads++;

	unsigned char* dec = (unsigned char*)malloc(j * 3 / 4 + 1);
	if (!dec) { free(clean); return -1; }
	int n = EVP_DecodeBlock(dec, (const unsigned char*)clean, j);
	free(clean);
	if (n < 0) { free(dec); return -1; }
	n -= pads;
	*out = dec;
	*out_len = n;
	return 0;
}

// Read one DER TLV at (*p,end); validate tag; advance *p to TLV end.
// Returns pointer to V and its length, or NULL on mismatch.
static const unsigned char* der_tlv(const unsigned char** p, const unsigned char* end,
	int expect_tag, long* vlen)
{
	if (*p >= end || **p != (unsigned char)expect_tag) return NULL;
	const unsigned char* q = *p + 1;
	long l;
	if (q >= end) return NULL;
	if (*q & 0x80)
	{
		int nb = *q & 0x7f;
		if (nb == 0 || nb > 4 || q + 1 + nb > end) return NULL;
		l = 0;
		for (int k = 0; k < nb; ++k) l = (l << 8) | q[1 + k];
		q += 1 + nb;
	}
	else
	{
		l = *q++;
	}
	if (q + l > end) return NULL;
	*p = q + l;
	if (vlen) *vlen = l;
	return q;
}

// Extract the signature blob (inner OCTET STRING) from a legacy request DER.
static int legacy_extract_blob(const unsigned char* d, int dlen,
	const unsigned char** blob, int* blob_len)
{
	const unsigned char* p = d;
	const unsigned char* end = d + dlen;
	long l;
	const unsigned char* q;

	q = der_tlv(&p, end, 0x30, &l);          // outer ContentInfo
	if (!q) return -1;
	const unsigned char* e1 = q + l; const unsigned char* c = q;
	if (!der_tlv(&c, e1, 0x06, NULL)) return -1;   // SPC timestamp request OID
	q = der_tlv(&c, e1, 0x30, &l);          // inner ContentInfo
	if (!q) return -1;
	const unsigned char* e2 = q + l; const unsigned char* i = q;
	if (!der_tlv(&i, e2, 0x06, NULL)) return -1;   // pkcs7-data OID
	q = der_tlv(&i, e2, 0xA0, &l);          // explicit [0]
	if (!q) return -1;
	const unsigned char* e3 = q + l; const unsigned char* k = q;
	q = der_tlv(&k, e3, 0x04, &l);          // OCTET STRING = encryptedDigest blob
	if (!q || l <= 0) return -1;
	*blob = q;
	*blob_len = (int)l;
	return 0;
}

static BIO* legacy_generate_response(const unsigned char* blob, int blob_len)
{
	BIO* mem_bio = NULL;
	PKCS7* p7 = NULL;
	PKCS7* encap = NULL;
	PKCS7_SIGNER_INFO* si = NULL;
	unsigned char* der = NULL;
	int ok = 0;

	p7 = PKCS7_new();
	if (!PKCS7_set_type(p7, NID_pkcs7_signed)) goto done;

	if (!PKCS7_content_new(p7, NID_pkcs7_data)) goto done;

	si = PKCS7_add_signature(p7, g_legacy_cert, g_legacy_pkey, EVP_sha256());
	if (!si) goto done;
	PKCS7_add_certificate(p7, g_legacy_cert);
	if (g_tsa_ca) PKCS7_add_certificate(p7, g_tsa_ca);


	{
		ASN1_OBJECT* cto = OBJ_nid2obj(NID_pkcs7_data);
		if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, cto))
			goto done;
	}
	{
		ASN1_UTCTIME* ut = fake_utctime_now();
		if (!ut) goto done;
		if (!PKCS7_add_signed_attribute(si, NID_pkcs9_signingTime, V_ASN1_UTCTIME, ut))
		{
			ASN1_UTCTIME_free(ut);
			goto done;
		}
	}

	{
		BIO* in = BIO_new_mem_buf(blob, blob_len);
	
		int r = in ? PKCS7_final(p7, in, PKCS7_BINARY) : 0;
		BIO_free(in);
		if (!r)
		{
			fprintf(stderr, "legacy PKCS7_final failed\n");
			ERR_print_errors_fp(stderr);
			goto done;
		}
	}

	{
		int derlen = i2d_PKCS7(p7, &der);
		if (derlen <= 0) goto done;

		mem_bio = BIO_new(BIO_s_mem());
		BIO* b64 = BIO_new(BIO_f_base64());
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
		BIO* chain = BIO_push(b64, mem_bio);
		BIO_write(chain, der, derlen);
		BIO_flush(chain);
		BIO_pop(b64);
		BIO_puts(mem_bio, "\r\n");
		OPENSSL_free(der);
		der = NULL;
	}
	ok = 1;

done:
	if (!ok)
	{
		BIO_free(mem_bio);
		mem_bio = NULL;
	}
	PKCS7_free(p7);
	PKCS7_free(encap);
	return mem_bio;
}


static int tst_time_callback(struct TS_resp_ctx* ctx, void* data,
	long* sec, long* usec)
{
	(void)ctx;
	(void)data;

	FakeUtc u = { 0 };
	fake_get_utc(&u);

	*sec  = u.epoch_sec;
	*usec = 0;
	{
		char lb[80];
		sprintf_s(lb, sizeof(lb), "genTime=20%02d%02d%02d%02d%02d%02dZ",
			u.year % 100, u.month, u.day,
			u.hour, u.minute, u.second);
		tsa_log("rfc3161 OK", lb);
	}
	return 1;
}

static BIO* tsp_generate_response(const unsigned char* req_data, int req_len)
{
	BIO* req_bio = BIO_new_mem_buf(req_data, req_len);
	if (!req_bio)
	{
		fprintf(stderr, "BIO_new_mem_buf failed\n");
		return NULL;
	}

	TS_RESP_CTX* ctx = TS_RESP_CTX_new();
	if (!ctx)
	{
		ERR_print_errors_fp(stderr);
		BIO_free(req_bio);
		return NULL;
	}

	TS_RESP_CTX_set_signer_cert(ctx, g_tsa_cert);
	TS_RESP_CTX_set_signer_key(ctx, g_tsa_pkey);
	TS_RESP_CTX_set_def_policy(ctx, g_ts_policy);

	TS_RESP_CTX_add_md(ctx, EVP_sha1());
	TS_RESP_CTX_add_md(ctx, EVP_sha256());
	TS_RESP_CTX_add_flags(ctx, TS_ESS_CERT_ID_CHAIN);
	TS_RESP_CTX_set_time_cb(ctx, tst_time_callback, NULL);

	
	if (g_tsa_ca)
	{
		STACK_OF(X509)* certs = sk_X509_new_null();
		if (certs)
		{
			sk_X509_push(certs, g_tsa_ca);
			TS_RESP_CTX_set_certs(ctx, certs);
			sk_X509_free(certs); 
		}
	}

	TS_RESP* ts_resp = TS_RESP_create_response(ctx, req_bio);
	BIO_free(req_bio); 
	if (!ts_resp)
	{
		fprintf(stderr, "TS_RESP_create_response failed\n");
		ERR_print_errors_fp(stderr);
		TS_RESP_CTX_free(ctx);
		return NULL;
	}

	BIO* out_bio = BIO_new(BIO_s_mem());
	if (!i2d_TS_RESP_bio(out_bio, ts_resp))
	{
		fprintf(stderr, "i2d_TS_RESP_bio failed\n");
		BIO_free(out_bio);
		TS_RESP_free(ts_resp);
		TS_RESP_CTX_free(ctx);
		return NULL;
	}

	TS_RESP_free(ts_resp);
	TS_RESP_CTX_free(ctx);
	return out_bio;
}


static char* stristr(const char* hay, const char* needle)
{
	for (; *hay; ++hay)
	{
		const char* h = hay;
		const char* n = needle;
		while (*n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) { ++h; ++n; }
		if (*n == 0) return (char*)hay;
	}
	return NULL;
}

static int send_all(SOCKET sock, const char* data, int len)
{
	while (len > 0)
	{
		int n = send(sock, data, len, 0);
		if (n <= 0) return -1;
		data += n;
		len -= n;
	}
	return 0;
}


static int http_recv_request(SOCKET sock, unsigned char** out_buf, int* out_header_len, int* out_body_len)
{
	int cap = 8192;
	int len = 0;
	int hlen = -1;
	long content_length = 0;
	unsigned char* b = (unsigned char*)malloc(cap);
	if (!b) return -1;

	*out_buf = NULL;
	*out_header_len = 0;
	*out_body_len = 0;

	while (hlen < 0)
	{
		if (len == cap)
		{
			if (cap >= 1024 * 1024) goto fail;
			cap *= 2;
			unsigned char* nb = (unsigned char*)realloc(b, cap);
			if (!nb) goto fail;
			b = nb;
		}
		int n = recv(sock, (char*)b + len, cap - len, 0);
		if (n <= 0) goto fail;
		len += n;
		b[len] = 0;
		unsigned char* sep = (unsigned char*)strstr((char*)b, "\r\n\r\n");
		if (sep) hlen = (int)(sep - b) + 4;
	}

	{
		unsigned char save2 = b[hlen - 4];
		b[hlen - 4] = 0;
		if (stristr((const char*)b, "expect:") != NULL &&
			stristr((const char*)b, "100-continue") != NULL)
		{
			send_all(sock, "HTTP/1.1 100 Continue\r\n\r\n", 25);
		}
		b[hlen - 4] = save2;
	}

	{
		char* p = stristr((char*)b, "content-length:");
		if (p)
		{
			p += (int)strlen("content-length:");
			while (*p == ' ' || *p == '\t') ++p;
			content_length = strtol(p, NULL, 10);
		}
	}
	if (content_length <= 0 || content_length > 16L * 1024 * 1024) goto fail;

	while (len - hlen < (int)content_length)
	{
		if (len == cap)
		{
			int need_cap = hlen + (int)content_length;
			int new_cap = cap;
			while (new_cap < need_cap) new_cap *= 2;
			unsigned char* nb = (unsigned char*)realloc(b, new_cap);
			if (!nb) goto fail;
			b = nb;
			cap = new_cap;
		}
		int n = recv(sock, (char*)b + len, cap - len, 0);
		if (n <= 0) goto fail;
		len += n;
	}

	*out_buf = b;
	*out_header_len = hlen;
	*out_body_len = (int)content_length;
	return 0;

fail:
	free(b);
	return -1;
}

static void handle_client(SOCKET sock)
{
	unsigned char* req_buf = NULL;
	int header_len = 0;
	int body_len = 0;
	BIO* resp_bio = NULL;
	long resp_len = 0;
	char* resp_data = NULL;
	char header[256] = { 0 };
	const unsigned char* body = NULL;
	int is_legacy = 0;
	const char* resp_content_type = "application/timestamp-response";
	unsigned char* der_req = NULL;
	int der_len = 0;
	const unsigned char* blob = NULL;
	int blob_len = 0;

	if (http_recv_request(sock, &req_buf, &header_len, &body_len) != 0)
	{
		const char* reply = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 11\r\n\r\nBad Request";
		send_all(sock, reply, (int)strlen(reply));
		goto end;
	}

	//  协议路由：
    //  -应用程序/八位字节流+base64文本->传统Authenticode会签
	//  -应用程序/时间戳查询/原始DER->RFC3161
	body = req_buf + header_len;
	{
		// 在截断以进行标头搜索之前捕获第一个正文字节
		unsigned char first = body_len > 0 ? body[0] : 0;
		char saved = (char)req_buf[header_len];
		req_buf[header_len] = 0;
		if (stristr((const char*)req_buf, "application/octet-stream") != NULL)
			is_legacy = 1;
		else if (body_len > 0 && first != 0x30)
			is_legacy = 1;
		req_buf[header_len] = (unsigned char)saved;
	}

	if (is_legacy)
	{
	
		int stage_dec = b64_strip_decode(body, body_len, &der_req, &der_len);
		int stage_ext = stage_dec ? -1 :
			legacy_extract_blob(der_req, der_len, &blob, &blob_len);
		if (stage_dec == 0 && stage_ext == 0)
			resp_bio = legacy_generate_response(blob, blob_len);
		if (!resp_bio)
		{
			char lb[160];
			sprintf_s(lb, sizeof(lb), "FAIL stage=%s body=%d der=%d blob=%d",
				stage_dec ? "base64" : (stage_ext ? "extract" : "generate"),
				body_len, der_len, blob_len);
			tsa_log("legacy", lb);
			fprintf(stderr, "旧流程失败：%s (body长度=%d der长度=%d blob长度=%d)\n",
				stage_dec ? "Base64解码" : (stage_ext ? "提取二进制块" : "生成响应数据"),
				body_len, der_len, blob_len);
			ERR_print_errors_fp(stderr);
		}
		free(der_req);
		resp_content_type = "application/octet-stream";
	}
	else
	{
		// RFC3161:body是二进制DER，可以合法地包含0x00字节。
		resp_bio = tsp_generate_response(body, body_len);
		if (!resp_bio)
		{
			tsa_log("rfc3161", "FAIL generate");
			
			ERR_print_errors_fp(stderr);
		}
	}

	if (!resp_bio)
	{
		const char* reply = "HTTP/1.1 500 Internal Error\r\nConnection: close\r\nContent-Length: 12\r\n\r\nTSA Gen Fail";
		send_all(sock, reply, (int)strlen(reply));
		goto end;
	}

	resp_len = BIO_pending(resp_bio);
	resp_data = (char*)malloc(resp_len);
	if (!resp_data) goto end;
	BIO_read(resp_bio, resp_data, resp_len);

	sprintf(header,
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: %s\r\n"
		"Connection: close\r\n"
		"Content-Length: %ld\r\n\r\n", resp_content_type, resp_len);
	send_all(sock, header, (int)strlen(header));
	send_all(sock, resp_data, (int)resp_len);

	free(resp_data);
	BIO_free(resp_bio);
end:
	free(req_buf);
	closesocket(sock);
}

int main(int argc, char** argv)
{
	(void)argc;
	(void)argv;

#ifdef _WIN32
	/* 内联 hook：让进程内其他时间查询同样返回伪造时间。
	 * Linux 下时间戳时间直接由回调/ini 生成，无需 hook。 */
	HMODULE basedll = GetModuleHandleA("kernelbase.dll");

	g_GetSystemTimeAsFileTime.SetHook(GetProcAddress(basedll,"GetSystemTimeAsFileTime"), MyGetSystemTimeAsFileTime);
	g_GetSystemTimePreciseAsFileTime.SetHook(GetProcAddress(basedll, "GetSystemTimePreciseAsFileTime"), MyGetSystemTimeAsFileTime);
	basedll = GetModuleHandleA("ntdll.dll");
	g_ZwQuerySystemTime.SetHook(GetProcAddress(basedll, "ZwQuerySystemTime"), MyZwQuerySystemTime);
#endif

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
	ERR_load_crypto_strings();

	if (!load_tsa_cert_key("tsa.crt", "tsa.key", "tsa_ca.crt"))
	{
		fprintf(stderr, "RFC3161 时间戳服务证书/密钥加载失败\n");
		return 1;
	}
	if (!load_legacy_assets("tsa_legacy.crt", "tsa_legacy.key"))
	{
		fprintf(stderr, "旧版时间戳服务证书/密钥加载失败\n");
		return 1;
	}

#ifdef _WIN32
	// Winsock 初始化
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#else
	// 避免向已关闭连接写数据时收到 SIGPIPE 导致进程退出
	signal(SIGPIPE, SIG_IGN);
#endif

	SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(LISTEN_PORT);
	bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
	listen(server_fd, 5);
	printf("RFC3161 时间戳服务服务器已在地址 http://localhost:%d\n", LISTEN_PORT);

	while (1)
	{
		SOCKET client = accept(server_fd, NULL, NULL);
		if (client == INVALID_SOCKET) continue;
		std::thread(handle_client, client).detach();
	}

	closesocket(server_fd);
	X509_free(g_tsa_cert);
	X509_free(g_tsa_ca);
	EVP_PKEY_free(g_tsa_pkey);
	ASN1_OBJECT_free(g_ts_policy);
	X509_free(g_legacy_cert);
	EVP_PKEY_free(g_legacy_pkey);
#ifdef _WIN32
	WSACleanup();
	g_GetSystemTimeAsFileTime.UnHook();
	g_GetSystemTimePreciseAsFileTime.UnHook();
#endif
	return 0;
	//GetSystemTimeAsFileTime
}


//g++ -O2 -std=c++17 -Wall -pthread -o DSign_server server.cpp -lssl -lcrypto -lpthread
//cat > /etc/systemd/system/dsign.service <<'EOF'
/*
cat > /etc/systemd/system/dsign.service <<'EOF'
[Unit]
Description=DSign TSA Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/admin/sign_web
ExecStart=/home/admin/sign_web/DSign_server
Restart=always
Environment=TZ=Asia/Shanghai

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now dsign
systemctl status dsign

*/

/*
systemctl daemon-reload
systemctl enable --now dsign

systemctl status dsign          # active (running) 即正常
ss -lntp | grep 8080            # 应看到 8080 端口在监听
journalctl -u dsign -f          # 实时看日志，有时间戳请求时会打印审计行
systemctl restart dsign     # 重启（改了 ini 或重新编译后）
systemctl stop dsign        # 停止
systemctl disable dsign     # 取消开机自启

万一以后想彻底删除它，也只影响它自己：

`systemctl disable --now dsign
rm -f /etc/systemd/system/dsign.service
systemctl daemon-reload`
*/