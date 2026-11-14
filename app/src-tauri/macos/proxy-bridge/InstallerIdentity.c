#include <Security/SecCode.h>
#include <Security/SecStaticCode.h>
#include <Security/SecBase.h>
#include <Security/SecRequirement.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

/* The live caller's code, found by its process id through the kernel. */
static SecCodeRef live_code(int32_t pid) {
    if (pid <= 0) return NULL;
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);
    if (!number) return NULL;
    const void *keys[] = {kSecGuestAttributePid};
    const void *values[] = {number};
    CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(number);
    if (!attrs) return NULL;
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
    CFRelease(attrs);
    return status == errSecSuccess ? code : NULL;
}

/* Is the live caller valid and does it satisfy `requirement` (the build's signing certificate)?
 * Unlike its code hash, this stays true for every later build signed the same way. */
int prism_macos_live_satisfies(int32_t pid, const char *requirement) {
    if (!requirement) return -1;
    SecCodeRef code = live_code(pid);
    if (!code) return -1;
    CFStringRef text = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
    SecRequirementRef req = NULL;
    OSStatus status = text ? SecRequirementCreateWithString(text, kSecCSDefaultFlags, &req) : errSecParam;
    if (text) CFRelease(text);
    if (status == errSecSuccess) status = SecCodeCheckValidity(code, kSecCSStrictValidate, req);
    if (req) CFRelease(req);
    CFRelease(code);
    return status == errSecSuccess ? 0 : -1;
}

/* The policy comes from the live caller's kernel code identity, not its path,
 * a UI field, an argument containing a hash, or the mutable app bundle. */
int prism_macos_live_cdhash(int32_t pid, char output[41]) {
    if (!output) return -1;
    SecCodeRef code = live_code(pid);
    if (!code) return -1;
    if (SecCodeCheckValidity(code, kSecCSStrictValidate, NULL) != errSecSuccess) { CFRelease(code); return -1; }
    CFDictionaryRef info = NULL;
    OSStatus status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    CFRelease(code);
    if (status != errSecSuccess || !info) return -1;
    CFTypeRef value = CFDictionaryGetValue(info, kSecCodeInfoUnique);
    if (!value || CFGetTypeID(value) != CFDataGetTypeID() || CFDataGetLength((CFDataRef)value) != 20) { CFRelease(info); return -1; }
    const UInt8 *bytes = CFDataGetBytePtr((CFDataRef)value);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 20; i++) { output[i*2] = hex[bytes[i] >> 4]; output[i*2+1] = hex[bytes[i] & 15]; }
    output[40] = 0;
    CFRelease(info);
    return 0;
}

#ifdef PRISM_INSTALLER_IDENTITY_TEST
#include <stdio.h>
int main(void) {
    char hash[41];
    if (prism_macos_live_cdhash((int32_t)getpid(), hash) != 0) return 1;
    puts(hash);
    return 0;
}
#endif
